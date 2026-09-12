"""
SentinelAI - WireGuard Noise Protocol Handshake Auditor
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for WireguardAuditor.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class WireguardAuditorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class WireguardAuditorHeader:
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
class WireguardAuditorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class WireguardAuditorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["WIREGUARDAUDITOR-R-0001"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0001",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0002"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0002",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0003"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0003",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0004"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0004",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0005"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0005",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0006"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0006",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0007"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0007",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0008"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0008",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0009"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0009",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0010"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0010",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0011"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0011",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0012"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0012",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0013"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0013",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0014"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0014",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0015"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0015",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0016"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0016",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0017"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0017",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0018"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0018",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0019"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0019",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0020"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0020",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0021"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0021",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0022"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0022",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0023"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0023",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0024"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0024",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0025"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0025",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0026"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0026",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0027"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0027",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0028"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0028",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0029"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0029",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0030"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0030",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0031"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0031",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0032"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0032",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0033"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0033",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0034"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0034",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0035"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0035",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0036"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0036",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0037"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0037",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0038"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0038",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0039"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0039",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0040"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0040",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0041"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0041",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0042"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0042",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0043"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0043",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0044"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0044",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0045"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0045",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0046"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0046",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0047"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0047",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0048"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0048",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0049"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0049",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0050"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0050",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0051"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0051",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0052"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0052",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0053"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0053",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0054"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0054",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0055"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0055",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0056"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0056",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0057"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0057",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0058"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0058",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0059"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0059",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0060"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0060",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0061"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0061",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0062"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0062",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0063"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0063",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0064"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0064",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0065"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0065",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0066"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0066",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0067"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0067",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0068"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0068",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0069"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0069",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0070"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0070",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0071"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0071",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0072"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0072",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0073"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0073",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0074"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0074",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0075"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0075",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0076"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0076",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0077"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0077",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0078"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0078",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0079"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0079",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0080"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0080",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0081"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0081",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0082"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0082",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0083"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0083",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0084"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0084",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0085"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0085",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0086"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0086",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0087"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0087",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0088"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0088",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0089"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0089",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0090"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0090",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0091"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0091",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0092"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0092",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0093"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0093",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0094"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0094",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0095"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0095",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0096"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0096",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0097"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0097",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0098"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0098",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0099"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0099",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0100"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0100",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0101"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0101",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0102"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0102",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0103"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0103",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0104"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0104",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0105"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0105",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0106"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0106",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0107"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0107",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0108"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0108",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0109"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0109",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0110"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0110",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0111"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0111",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0112"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0112",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0113"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0113",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0114"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0114",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0115"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0115",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0116"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0116",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0117"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0117",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0118"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0118",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0119"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0119",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0120"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0120",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0121"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0121",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0122"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0122",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0123"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0123",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0124"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0124",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0125"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0125",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0126"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0126",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0127"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0127",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0128"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0128",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0129"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0129",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0130"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0130",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0131"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0131",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0132"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0132",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0133"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0133",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0134"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0134",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0135"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0135",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0136"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0136",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0137"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0137",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0138"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0138",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0139"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0139",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0140"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0140",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0141"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0141",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0142"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0142",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0143"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0143",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0144"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0144",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0145"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0145",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0146"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0146",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0147"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0147",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0148"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0148",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0149"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0149",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0150"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0150",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0151"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0151",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0152"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0152",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0153"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0153",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0154"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0154",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0155"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0155",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0156"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0156",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0157"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0157",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0158"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0158",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0159"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0159",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0160"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0160",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0161"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0161",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0162"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0162",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0163"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0163",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0164"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0164",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0165"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0165",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0166"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0166",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0167"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0167",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0168"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0168",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0169"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0169",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0170"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0170",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0171"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0171",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0172"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0172",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0173"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0173",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0174"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0174",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0175"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0175",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0176"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0176",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0177"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0177",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0178"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0178",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0179"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0179",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0180"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0180",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0181"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0181",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0182"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0182",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0183"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0183",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0184"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0184",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0185"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0185",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0186"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0186",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0187"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0187",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0188"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0188",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0189"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0189",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0190"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0190",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0191"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0191",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0192"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0192",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0193"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0193",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0194"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0194",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0195"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0195",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0196"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0196",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0197"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0197",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0198"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0198",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0199"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0199",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0200"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0200",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0201"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0201",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0202"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0202",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0203"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0203",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0204"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0204",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0205"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0205",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0206"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0206",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0207"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0207",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0208"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0208",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0209"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0209",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0210"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0210",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0211"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0211",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0212"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0212",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0213"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0213",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0214"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0214",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0215"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0215",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0216"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0216",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0217"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0217",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0218"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0218",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0219"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0219",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0220"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0220",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0221"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0221",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0222"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0222",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0223"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0223",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0224"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0224",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0225"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0225",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0226"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0226",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0227"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0227",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0228"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0228",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0229"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0229",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0230"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0230",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0231"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0231",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0232"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0232",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0233"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0233",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0234"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0234",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0235"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0235",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0236"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0236",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0237"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0237",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0238"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0238",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0239"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0239",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0240"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0240",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0241"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0241",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0242"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0242",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0243"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0243",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0244"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0244",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0245"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0245",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0246"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0246",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0247"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0247",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0248"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0248",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0249"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0249",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0250"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0250",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0251"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0251",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0252"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0252",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0253"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0253",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0254"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0254",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0255"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0255",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0256"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0256",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0257"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0257",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0258"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0258",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0259"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0259",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0260"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0260",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0261"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0261",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0262"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0262",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0263"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0263",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0264"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0264",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0265"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0265",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0266"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0266",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0267"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0267",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0268"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0268",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0269"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0269",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0270"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0270",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0271"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0271",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0272"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0272",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0273"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0273",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0274"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0274",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0275"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0275",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0276"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0276",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0277"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0277",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0278"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0278",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0279"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0279",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0280"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0280",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0281"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0281",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0282"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0282",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0283"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0283",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0284"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0284",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0285"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0285",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0286"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0286",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0287"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0287",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0288"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0288",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0289"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0289",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0290"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0290",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0291"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0291",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0292"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0292",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0293"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0293",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0294"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0294",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0295"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0295",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0296"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0296",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0297"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0297",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0298"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0298",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0299"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0299",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0300"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0300",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0301"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0301",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0302"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0302",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0303"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0303",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0304"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0304",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0305"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0305",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0306"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0306",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0307"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0307",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0308"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0308",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0309"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0309",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0310"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0310",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0311"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0311",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0312"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0312",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0313"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0313",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0314"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0314",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0315"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0315",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0316"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0316",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0317"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0317",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0318"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0318",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0319"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0319",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0320"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0320",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0321"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0321",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0322"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0322",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0323"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0323",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0324"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0324",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0325"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0325",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0326"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0326",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0327"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0327",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0328"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0328",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0329"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0329",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0330"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0330",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0331"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0331",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0332"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0332",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0333"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0333",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0334"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0334",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0335"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0335",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0336"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0336",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0337"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0337",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0338"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0338",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0339"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0339",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0340"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0340",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0341"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0341",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0342"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0342",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0343"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0343",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0344"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0344",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0345"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0345",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0346"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0346",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0347"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0347",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0348"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0348",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0349"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0349",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0350"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0350",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0351"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0351",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0352"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0352",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0353"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0353",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0354"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0354",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0355"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0355",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0356"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0356",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0357"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0357",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0358"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0358",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0359"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0359",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0360"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0360",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0361"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0361",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0362"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0362",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0363"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0363",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0364"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0364",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0365"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0365",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0366"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0366",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0367"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0367",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0368"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0368",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0369"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0369",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0370"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0370",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0371"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0371",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0372"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0372",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0373"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0373",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0374"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0374",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0375"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0375",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0376"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0376",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0377"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0377",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0378"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0378",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0379"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0379",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0380"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0380",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0381"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0381",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0382"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0382",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0383"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0383",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0384"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0384",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0385"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0385",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0386"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0386",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0387"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0387",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0388"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0388",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0389"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0389",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0390"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0390",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0391"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0391",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0392"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0392",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0393"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0393",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0394"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0394",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0395"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0395",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0396"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0396",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0397"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0397",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0398"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0398",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0399"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0399",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0400"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0400",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0401"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0401",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0402"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0402",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0403"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0403",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0404"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0404",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0405"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0405",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0406"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0406",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0407"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0407",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0408"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0408",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0409"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0409",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0410"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0410",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0411"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0411",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0412"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0412",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0413"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0413",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0414"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0414",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0415"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0415",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0416"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0416",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0417"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0417",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0418"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0418",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0419"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0419",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0420"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0420",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0421"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0421",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0422"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0422",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0423"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0423",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0424"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0424",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0425"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0425",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0426"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0426",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0427"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0427",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0428"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0428",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0429"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0429",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0430"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0430",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0431"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0431",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0432"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0432",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0433"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0433",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0434"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0434",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0435"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0435",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0436"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0436",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0437"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0437",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0438"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0438",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0439"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0439",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0440"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0440",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0441"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0441",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0442"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0442",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0443"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0443",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0444"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0444",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0445"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0445",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0446"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0446",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0447"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0447",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0448"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0448",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["WIREGUARDAUDITOR-R-0449"] = WireguardAuditorRule(
            rule_id="WIREGUARDAUDITOR-R-0449",
            name="WireGuard Noise Protocol Handshake Auditor Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: WireguardAuditorHeader) -> Dict[str, Any]:
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

wireguard_noise_auditor_instance = WireguardAuditorEngine()

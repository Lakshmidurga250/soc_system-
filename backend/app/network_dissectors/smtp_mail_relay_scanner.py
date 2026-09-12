"""
SentinelAI - SMTP Mail Relay & Header Forgery Security Scanner
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for SmtpScanner.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class SmtpScannerState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class SmtpScannerHeader:
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
class SmtpScannerRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class SmtpScannerEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["SMTPSCANNER-R-0001"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0001",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0002"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0002",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0003"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0003",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0004"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0004",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0005"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0005",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0006"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0006",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0007"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0007",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0008"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0008",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0009"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0009",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0010"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0010",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0011"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0011",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0012"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0012",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0013"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0013",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0014"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0014",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0015"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0015",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0016"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0016",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0017"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0017",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0018"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0018",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0019"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0019",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0020"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0020",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0021"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0021",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0022"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0022",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0023"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0023",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0024"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0024",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0025"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0025",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0026"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0026",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0027"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0027",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0028"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0028",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0029"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0029",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0030"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0030",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0031"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0031",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0032"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0032",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0033"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0033",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0034"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0034",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0035"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0035",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0036"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0036",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0037"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0037",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0038"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0038",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0039"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0039",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0040"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0040",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0041"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0041",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0042"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0042",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0043"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0043",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0044"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0044",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0045"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0045",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0046"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0046",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0047"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0047",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0048"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0048",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0049"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0049",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0050"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0050",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0051"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0051",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0052"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0052",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0053"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0053",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0054"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0054",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0055"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0055",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0056"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0056",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0057"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0057",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0058"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0058",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0059"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0059",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0060"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0060",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0061"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0061",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0062"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0062",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0063"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0063",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0064"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0064",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0065"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0065",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0066"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0066",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0067"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0067",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0068"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0068",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0069"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0069",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0070"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0070",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0071"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0071",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0072"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0072",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0073"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0073",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0074"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0074",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0075"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0075",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0076"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0076",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0077"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0077",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0078"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0078",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0079"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0079",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0080"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0080",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0081"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0081",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0082"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0082",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0083"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0083",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0084"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0084",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0085"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0085",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0086"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0086",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0087"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0087",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0088"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0088",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0089"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0089",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0090"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0090",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0091"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0091",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0092"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0092",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0093"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0093",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0094"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0094",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0095"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0095",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0096"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0096",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0097"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0097",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0098"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0098",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0099"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0099",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0100"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0100",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0101"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0101",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0102"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0102",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0103"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0103",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0104"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0104",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0105"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0105",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0106"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0106",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0107"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0107",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0108"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0108",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0109"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0109",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0110"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0110",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0111"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0111",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0112"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0112",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0113"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0113",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0114"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0114",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0115"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0115",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0116"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0116",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0117"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0117",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0118"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0118",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0119"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0119",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0120"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0120",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0121"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0121",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0122"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0122",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0123"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0123",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0124"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0124",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0125"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0125",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0126"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0126",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0127"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0127",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0128"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0128",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0129"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0129",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0130"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0130",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0131"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0131",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0132"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0132",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0133"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0133",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0134"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0134",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0135"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0135",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0136"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0136",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0137"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0137",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0138"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0138",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0139"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0139",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0140"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0140",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0141"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0141",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0142"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0142",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0143"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0143",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0144"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0144",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0145"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0145",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0146"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0146",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0147"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0147",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0148"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0148",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0149"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0149",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0150"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0150",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0151"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0151",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0152"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0152",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0153"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0153",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0154"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0154",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0155"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0155",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0156"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0156",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0157"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0157",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0158"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0158",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0159"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0159",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0160"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0160",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0161"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0161",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0162"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0162",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0163"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0163",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0164"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0164",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0165"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0165",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0166"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0166",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0167"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0167",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0168"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0168",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0169"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0169",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0170"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0170",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0171"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0171",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0172"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0172",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0173"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0173",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0174"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0174",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0175"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0175",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0176"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0176",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0177"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0177",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0178"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0178",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0179"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0179",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0180"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0180",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0181"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0181",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0182"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0182",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0183"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0183",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0184"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0184",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0185"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0185",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0186"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0186",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0187"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0187",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0188"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0188",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0189"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0189",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0190"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0190",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0191"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0191",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0192"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0192",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0193"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0193",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0194"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0194",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0195"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0195",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0196"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0196",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0197"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0197",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0198"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0198",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0199"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0199",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0200"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0200",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0201"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0201",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0202"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0202",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0203"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0203",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0204"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0204",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0205"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0205",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0206"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0206",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0207"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0207",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0208"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0208",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0209"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0209",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0210"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0210",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0211"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0211",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0212"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0212",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0213"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0213",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0214"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0214",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0215"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0215",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0216"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0216",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0217"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0217",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0218"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0218",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0219"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0219",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0220"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0220",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0221"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0221",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0222"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0222",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0223"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0223",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0224"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0224",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0225"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0225",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0226"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0226",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0227"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0227",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0228"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0228",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0229"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0229",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0230"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0230",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0231"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0231",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0232"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0232",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0233"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0233",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0234"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0234",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0235"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0235",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0236"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0236",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0237"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0237",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0238"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0238",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0239"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0239",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0240"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0240",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0241"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0241",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0242"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0242",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0243"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0243",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0244"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0244",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0245"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0245",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0246"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0246",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0247"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0247",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0248"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0248",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0249"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0249",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0250"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0250",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0251"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0251",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0252"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0252",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0253"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0253",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0254"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0254",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0255"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0255",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0256"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0256",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0257"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0257",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0258"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0258",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0259"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0259",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0260"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0260",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0261"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0261",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0262"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0262",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0263"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0263",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0264"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0264",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0265"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0265",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0266"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0266",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0267"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0267",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0268"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0268",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0269"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0269",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0270"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0270",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0271"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0271",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0272"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0272",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0273"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0273",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0274"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0274",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0275"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0275",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0276"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0276",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0277"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0277",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0278"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0278",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0279"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0279",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0280"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0280",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0281"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0281",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0282"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0282",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0283"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0283",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0284"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0284",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0285"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0285",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0286"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0286",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0287"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0287",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0288"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0288",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0289"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0289",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0290"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0290",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0291"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0291",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0292"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0292",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0293"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0293",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0294"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0294",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0295"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0295",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0296"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0296",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0297"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0297",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0298"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0298",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0299"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0299",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0300"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0300",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0301"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0301",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0302"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0302",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0303"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0303",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0304"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0304",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0305"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0305",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0306"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0306",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0307"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0307",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0308"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0308",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0309"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0309",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0310"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0310",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0311"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0311",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0312"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0312",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0313"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0313",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0314"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0314",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0315"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0315",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0316"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0316",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0317"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0317",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0318"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0318",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0319"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0319",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0320"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0320",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0321"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0321",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0322"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0322",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0323"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0323",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0324"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0324",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0325"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0325",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0326"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0326",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0327"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0327",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0328"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0328",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0329"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0329",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0330"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0330",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0331"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0331",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0332"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0332",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0333"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0333",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0334"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0334",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0335"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0335",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0336"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0336",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0337"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0337",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0338"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0338",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0339"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0339",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0340"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0340",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0341"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0341",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0342"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0342",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0343"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0343",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0344"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0344",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0345"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0345",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0346"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0346",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0347"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0347",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0348"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0348",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0349"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0349",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0350"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0350",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0351"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0351",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0352"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0352",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0353"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0353",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0354"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0354",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0355"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0355",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0356"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0356",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0357"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0357",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0358"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0358",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0359"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0359",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0360"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0360",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0361"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0361",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0362"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0362",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0363"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0363",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0364"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0364",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0365"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0365",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0366"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0366",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0367"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0367",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0368"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0368",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0369"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0369",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0370"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0370",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0371"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0371",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0372"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0372",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0373"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0373",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0374"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0374",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0375"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0375",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0376"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0376",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0377"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0377",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0378"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0378",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0379"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0379",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0380"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0380",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0381"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0381",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0382"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0382",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0383"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0383",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0384"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0384",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0385"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0385",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0386"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0386",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0387"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0387",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0388"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0388",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0389"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0389",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0390"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0390",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0391"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0391",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0392"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0392",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0393"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0393",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0394"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0394",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0395"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0395",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0396"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0396",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0397"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0397",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0398"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0398",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0399"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0399",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0400"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0400",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0401"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0401",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0402"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0402",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0403"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0403",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0404"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0404",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0405"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0405",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0406"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0406",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0407"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0407",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0408"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0408",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0409"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0409",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0410"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0410",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0411"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0411",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0412"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0412",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0413"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0413",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0414"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0414",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0415"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0415",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0416"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0416",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0417"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0417",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0418"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0418",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0419"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0419",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0420"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0420",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0421"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0421",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0422"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0422",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0423"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0423",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0424"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0424",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0425"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0425",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0426"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0426",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0427"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0427",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0428"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0428",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0429"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0429",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0430"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0430",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0431"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0431",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0432"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0432",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0433"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0433",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0434"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0434",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0435"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0435",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0436"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0436",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0437"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0437",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0438"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0438",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0439"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0439",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0440"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0440",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0441"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0441",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0442"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0442",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0443"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0443",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0444"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0444",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0445"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0445",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0446"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0446",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0447"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0447",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0448"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0448",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMTPSCANNER-R-0449"] = SmtpScannerRule(
            rule_id="SMTPSCANNER-R-0449",
            name="SMTP Mail Relay & Header Forgery Security Scanner Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: SmtpScannerHeader) -> Dict[str, Any]:
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

smtp_mail_relay_scanner_instance = SmtpScannerEngine()

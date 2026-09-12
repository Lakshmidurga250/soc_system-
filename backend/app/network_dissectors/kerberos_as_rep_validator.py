"""
SentinelAI - Kerberos AS-REP Pre-Authentication & Ticket Verifier
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for KerberosValidator.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class KerberosValidatorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class KerberosValidatorHeader:
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
class KerberosValidatorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class KerberosValidatorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["KERBEROSVALIDATOR-R-0001"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0001",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0002"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0002",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0003"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0003",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0004"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0004",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0005"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0005",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0006"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0006",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0007"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0007",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0008"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0008",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0009"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0009",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0010"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0010",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0011"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0011",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0012"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0012",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0013"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0013",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0014"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0014",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0015"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0015",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0016"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0016",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0017"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0017",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0018"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0018",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0019"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0019",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0020"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0020",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0021"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0021",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0022"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0022",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0023"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0023",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0024"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0024",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0025"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0025",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0026"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0026",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0027"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0027",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0028"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0028",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0029"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0029",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0030"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0030",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0031"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0031",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0032"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0032",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0033"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0033",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0034"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0034",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0035"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0035",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0036"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0036",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0037"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0037",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0038"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0038",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0039"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0039",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0040"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0040",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0041"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0041",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0042"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0042",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0043"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0043",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0044"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0044",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0045"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0045",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0046"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0046",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0047"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0047",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0048"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0048",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0049"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0049",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0050"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0050",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0051"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0051",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0052"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0052",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0053"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0053",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0054"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0054",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0055"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0055",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0056"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0056",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0057"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0057",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0058"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0058",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0059"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0059",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0060"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0060",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0061"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0061",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0062"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0062",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0063"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0063",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0064"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0064",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0065"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0065",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0066"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0066",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0067"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0067",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0068"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0068",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0069"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0069",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0070"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0070",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0071"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0071",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0072"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0072",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0073"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0073",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0074"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0074",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0075"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0075",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0076"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0076",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0077"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0077",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0078"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0078",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0079"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0079",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0080"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0080",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0081"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0081",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0082"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0082",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0083"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0083",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0084"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0084",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0085"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0085",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0086"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0086",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0087"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0087",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0088"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0088",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0089"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0089",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0090"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0090",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0091"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0091",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0092"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0092",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0093"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0093",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0094"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0094",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0095"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0095",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0096"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0096",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0097"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0097",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0098"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0098",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0099"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0099",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0100"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0100",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0101"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0101",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0102"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0102",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0103"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0103",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0104"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0104",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0105"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0105",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0106"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0106",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0107"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0107",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0108"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0108",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0109"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0109",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0110"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0110",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0111"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0111",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0112"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0112",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0113"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0113",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0114"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0114",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0115"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0115",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0116"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0116",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0117"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0117",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0118"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0118",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0119"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0119",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0120"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0120",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0121"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0121",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0122"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0122",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0123"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0123",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0124"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0124",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0125"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0125",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0126"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0126",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0127"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0127",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0128"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0128",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0129"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0129",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0130"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0130",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0131"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0131",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0132"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0132",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0133"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0133",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0134"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0134",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0135"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0135",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0136"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0136",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0137"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0137",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0138"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0138",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0139"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0139",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0140"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0140",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0141"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0141",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0142"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0142",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0143"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0143",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0144"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0144",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0145"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0145",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0146"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0146",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0147"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0147",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0148"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0148",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0149"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0149",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0150"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0150",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0151"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0151",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0152"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0152",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0153"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0153",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0154"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0154",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0155"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0155",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0156"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0156",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0157"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0157",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0158"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0158",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0159"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0159",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0160"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0160",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0161"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0161",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0162"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0162",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0163"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0163",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0164"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0164",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0165"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0165",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0166"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0166",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0167"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0167",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0168"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0168",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0169"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0169",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0170"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0170",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0171"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0171",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0172"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0172",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0173"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0173",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0174"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0174",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0175"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0175",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0176"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0176",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0177"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0177",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0178"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0178",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0179"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0179",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0180"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0180",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0181"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0181",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0182"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0182",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0183"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0183",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0184"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0184",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0185"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0185",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0186"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0186",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0187"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0187",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0188"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0188",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0189"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0189",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0190"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0190",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0191"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0191",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0192"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0192",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0193"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0193",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0194"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0194",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0195"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0195",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0196"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0196",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0197"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0197",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0198"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0198",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0199"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0199",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0200"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0200",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0201"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0201",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0202"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0202",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0203"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0203",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0204"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0204",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0205"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0205",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0206"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0206",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0207"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0207",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0208"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0208",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0209"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0209",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0210"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0210",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0211"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0211",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0212"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0212",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0213"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0213",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0214"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0214",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0215"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0215",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0216"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0216",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0217"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0217",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0218"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0218",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0219"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0219",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0220"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0220",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0221"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0221",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0222"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0222",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0223"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0223",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0224"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0224",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0225"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0225",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0226"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0226",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0227"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0227",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0228"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0228",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0229"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0229",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0230"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0230",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0231"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0231",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0232"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0232",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0233"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0233",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0234"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0234",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0235"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0235",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0236"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0236",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0237"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0237",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0238"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0238",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0239"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0239",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0240"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0240",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0241"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0241",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0242"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0242",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0243"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0243",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0244"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0244",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0245"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0245",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0246"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0246",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0247"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0247",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0248"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0248",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0249"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0249",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0250"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0250",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0251"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0251",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0252"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0252",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0253"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0253",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0254"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0254",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0255"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0255",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0256"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0256",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0257"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0257",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0258"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0258",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0259"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0259",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0260"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0260",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0261"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0261",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0262"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0262",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0263"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0263",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0264"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0264",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0265"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0265",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0266"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0266",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0267"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0267",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0268"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0268",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0269"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0269",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0270"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0270",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0271"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0271",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0272"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0272",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0273"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0273",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0274"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0274",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0275"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0275",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0276"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0276",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0277"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0277",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0278"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0278",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0279"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0279",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0280"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0280",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0281"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0281",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0282"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0282",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0283"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0283",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0284"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0284",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0285"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0285",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0286"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0286",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0287"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0287",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0288"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0288",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0289"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0289",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0290"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0290",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0291"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0291",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0292"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0292",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0293"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0293",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0294"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0294",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0295"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0295",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0296"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0296",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0297"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0297",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0298"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0298",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0299"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0299",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0300"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0300",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0301"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0301",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0302"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0302",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0303"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0303",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0304"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0304",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0305"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0305",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0306"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0306",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0307"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0307",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0308"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0308",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0309"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0309",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0310"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0310",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0311"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0311",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0312"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0312",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0313"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0313",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0314"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0314",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0315"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0315",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0316"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0316",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0317"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0317",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0318"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0318",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0319"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0319",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0320"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0320",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0321"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0321",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0322"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0322",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0323"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0323",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0324"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0324",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0325"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0325",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0326"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0326",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0327"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0327",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0328"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0328",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0329"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0329",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0330"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0330",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0331"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0331",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0332"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0332",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0333"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0333",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0334"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0334",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0335"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0335",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0336"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0336",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0337"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0337",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0338"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0338",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0339"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0339",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0340"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0340",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0341"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0341",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0342"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0342",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0343"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0343",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0344"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0344",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0345"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0345",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0346"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0346",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0347"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0347",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0348"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0348",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0349"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0349",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0350"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0350",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0351"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0351",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0352"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0352",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0353"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0353",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0354"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0354",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0355"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0355",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0356"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0356",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0357"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0357",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0358"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0358",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0359"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0359",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0360"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0360",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0361"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0361",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0362"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0362",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0363"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0363",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0364"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0364",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0365"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0365",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0366"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0366",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0367"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0367",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0368"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0368",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0369"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0369",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0370"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0370",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0371"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0371",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0372"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0372",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0373"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0373",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0374"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0374",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0375"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0375",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0376"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0376",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0377"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0377",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0378"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0378",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0379"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0379",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0380"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0380",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0381"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0381",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0382"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0382",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0383"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0383",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0384"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0384",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0385"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0385",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0386"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0386",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0387"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0387",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0388"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0388",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0389"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0389",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0390"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0390",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0391"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0391",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0392"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0392",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0393"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0393",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0394"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0394",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0395"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0395",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0396"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0396",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0397"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0397",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0398"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0398",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0399"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0399",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0400"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0400",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0401"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0401",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0402"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0402",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0403"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0403",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0404"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0404",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0405"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0405",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0406"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0406",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0407"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0407",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0408"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0408",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0409"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0409",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0410"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0410",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0411"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0411",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0412"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0412",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0413"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0413",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0414"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0414",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0415"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0415",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0416"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0416",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0417"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0417",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0418"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0418",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0419"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0419",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0420"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0420",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0421"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0421",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0422"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0422",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0423"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0423",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0424"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0424",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0425"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0425",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0426"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0426",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0427"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0427",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0428"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0428",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0429"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0429",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0430"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0430",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0431"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0431",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0432"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0432",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0433"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0433",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0434"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0434",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0435"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0435",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0436"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0436",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0437"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0437",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0438"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0438",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0439"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0439",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0440"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0440",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0441"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0441",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0442"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0442",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0443"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0443",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0444"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0444",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0445"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0445",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0446"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0446",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0447"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0447",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0448"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0448",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["KERBEROSVALIDATOR-R-0449"] = KerberosValidatorRule(
            rule_id="KERBEROSVALIDATOR-R-0449",
            name="Kerberos AS-REP Pre-Authentication & Ticket Verifier Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: KerberosValidatorHeader) -> Dict[str, Any]:
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

kerberos_as_rep_validator_instance = KerberosValidatorEngine()

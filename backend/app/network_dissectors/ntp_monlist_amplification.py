"""
SentinelAI - NTP Monlist Reflection & Timestamp Skew Detector
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for NtpSkewDetector.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class NtpSkewDetectorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class NtpSkewDetectorHeader:
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
class NtpSkewDetectorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class NtpSkewDetectorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["NTPSKEWDETECTOR-R-0001"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0001",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0002"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0002",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0003"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0003",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0004"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0004",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0005"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0005",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0006"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0006",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0007"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0007",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0008"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0008",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0009"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0009",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0010"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0010",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0011"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0011",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0012"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0012",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0013"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0013",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0014"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0014",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0015"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0015",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0016"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0016",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0017"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0017",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0018"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0018",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0019"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0019",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0020"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0020",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0021"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0021",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0022"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0022",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0023"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0023",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0024"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0024",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0025"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0025",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0026"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0026",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0027"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0027",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0028"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0028",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0029"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0029",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0030"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0030",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0031"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0031",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0032"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0032",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0033"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0033",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0034"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0034",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0035"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0035",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0036"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0036",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0037"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0037",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0038"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0038",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0039"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0039",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0040"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0040",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0041"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0041",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0042"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0042",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0043"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0043",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0044"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0044",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0045"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0045",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0046"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0046",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0047"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0047",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0048"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0048",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0049"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0049",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0050"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0050",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0051"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0051",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0052"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0052",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0053"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0053",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0054"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0054",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0055"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0055",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0056"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0056",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0057"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0057",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0058"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0058",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0059"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0059",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0060"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0060",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0061"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0061",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0062"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0062",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0063"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0063",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0064"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0064",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0065"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0065",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0066"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0066",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0067"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0067",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0068"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0068",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0069"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0069",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0070"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0070",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0071"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0071",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0072"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0072",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0073"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0073",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0074"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0074",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0075"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0075",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0076"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0076",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0077"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0077",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0078"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0078",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0079"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0079",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0080"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0080",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0081"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0081",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0082"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0082",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0083"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0083",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0084"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0084",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0085"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0085",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0086"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0086",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0087"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0087",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0088"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0088",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0089"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0089",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0090"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0090",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0091"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0091",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0092"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0092",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0093"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0093",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0094"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0094",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0095"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0095",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0096"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0096",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0097"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0097",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0098"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0098",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0099"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0099",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0100"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0100",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0101"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0101",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0102"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0102",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0103"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0103",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0104"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0104",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0105"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0105",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0106"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0106",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0107"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0107",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0108"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0108",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0109"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0109",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0110"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0110",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0111"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0111",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0112"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0112",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0113"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0113",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0114"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0114",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0115"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0115",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0116"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0116",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0117"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0117",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0118"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0118",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0119"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0119",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0120"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0120",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0121"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0121",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0122"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0122",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0123"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0123",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0124"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0124",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0125"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0125",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0126"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0126",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0127"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0127",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0128"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0128",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0129"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0129",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0130"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0130",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0131"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0131",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0132"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0132",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0133"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0133",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0134"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0134",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0135"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0135",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0136"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0136",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0137"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0137",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0138"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0138",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0139"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0139",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0140"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0140",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0141"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0141",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0142"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0142",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0143"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0143",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0144"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0144",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0145"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0145",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0146"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0146",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0147"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0147",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0148"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0148",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0149"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0149",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0150"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0150",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0151"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0151",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0152"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0152",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0153"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0153",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0154"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0154",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0155"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0155",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0156"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0156",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0157"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0157",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0158"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0158",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0159"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0159",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0160"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0160",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0161"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0161",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0162"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0162",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0163"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0163",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0164"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0164",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0165"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0165",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0166"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0166",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0167"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0167",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0168"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0168",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0169"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0169",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0170"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0170",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0171"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0171",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0172"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0172",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0173"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0173",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0174"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0174",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0175"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0175",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0176"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0176",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0177"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0177",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0178"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0178",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0179"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0179",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0180"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0180",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0181"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0181",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0182"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0182",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0183"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0183",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0184"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0184",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0185"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0185",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0186"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0186",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0187"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0187",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0188"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0188",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0189"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0189",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0190"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0190",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0191"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0191",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0192"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0192",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0193"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0193",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0194"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0194",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0195"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0195",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0196"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0196",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0197"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0197",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0198"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0198",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0199"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0199",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0200"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0200",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0201"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0201",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0202"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0202",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0203"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0203",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0204"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0204",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0205"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0205",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0206"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0206",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0207"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0207",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0208"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0208",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0209"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0209",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0210"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0210",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0211"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0211",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0212"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0212",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0213"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0213",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0214"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0214",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0215"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0215",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0216"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0216",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0217"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0217",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0218"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0218",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0219"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0219",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0220"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0220",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0221"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0221",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0222"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0222",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0223"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0223",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0224"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0224",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0225"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0225",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0226"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0226",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0227"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0227",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0228"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0228",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0229"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0229",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0230"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0230",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0231"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0231",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0232"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0232",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0233"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0233",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0234"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0234",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0235"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0235",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0236"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0236",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0237"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0237",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0238"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0238",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0239"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0239",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0240"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0240",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0241"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0241",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0242"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0242",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0243"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0243",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0244"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0244",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0245"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0245",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0246"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0246",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0247"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0247",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0248"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0248",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0249"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0249",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0250"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0250",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0251"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0251",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0252"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0252",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0253"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0253",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0254"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0254",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0255"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0255",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0256"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0256",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0257"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0257",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0258"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0258",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0259"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0259",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0260"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0260",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0261"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0261",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0262"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0262",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0263"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0263",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0264"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0264",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0265"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0265",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0266"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0266",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0267"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0267",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0268"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0268",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0269"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0269",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0270"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0270",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0271"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0271",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0272"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0272",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0273"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0273",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0274"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0274",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0275"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0275",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0276"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0276",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0277"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0277",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0278"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0278",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0279"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0279",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0280"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0280",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0281"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0281",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0282"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0282",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0283"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0283",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0284"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0284",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0285"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0285",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0286"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0286",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0287"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0287",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0288"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0288",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0289"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0289",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0290"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0290",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0291"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0291",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0292"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0292",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0293"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0293",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0294"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0294",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0295"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0295",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0296"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0296",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0297"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0297",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0298"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0298",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0299"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0299",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0300"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0300",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0301"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0301",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0302"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0302",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0303"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0303",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0304"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0304",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0305"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0305",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0306"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0306",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0307"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0307",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0308"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0308",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0309"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0309",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0310"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0310",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0311"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0311",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0312"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0312",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0313"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0313",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0314"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0314",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0315"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0315",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0316"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0316",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0317"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0317",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0318"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0318",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0319"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0319",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0320"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0320",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0321"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0321",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0322"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0322",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0323"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0323",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0324"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0324",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0325"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0325",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0326"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0326",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0327"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0327",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0328"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0328",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0329"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0329",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0330"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0330",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0331"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0331",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0332"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0332",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0333"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0333",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0334"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0334",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0335"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0335",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0336"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0336",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0337"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0337",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0338"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0338",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0339"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0339",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0340"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0340",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0341"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0341",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0342"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0342",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0343"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0343",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0344"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0344",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0345"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0345",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0346"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0346",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0347"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0347",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0348"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0348",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0349"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0349",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0350"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0350",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0351"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0351",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0352"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0352",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0353"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0353",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0354"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0354",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0355"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0355",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0356"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0356",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0357"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0357",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0358"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0358",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0359"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0359",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0360"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0360",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0361"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0361",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0362"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0362",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0363"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0363",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0364"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0364",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0365"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0365",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0366"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0366",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0367"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0367",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0368"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0368",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0369"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0369",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0370"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0370",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0371"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0371",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0372"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0372",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0373"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0373",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0374"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0374",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0375"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0375",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0376"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0376",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0377"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0377",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0378"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0378",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0379"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0379",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0380"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0380",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0381"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0381",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0382"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0382",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0383"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0383",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0384"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0384",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0385"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0385",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0386"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0386",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0387"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0387",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0388"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0388",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0389"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0389",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0390"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0390",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0391"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0391",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0392"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0392",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0393"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0393",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0394"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0394",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0395"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0395",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0396"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0396",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0397"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0397",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0398"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0398",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0399"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0399",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0400"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0400",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0401"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0401",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0402"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0402",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0403"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0403",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0404"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0404",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0405"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0405",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0406"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0406",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0407"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0407",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0408"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0408",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0409"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0409",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0410"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0410",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0411"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0411",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0412"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0412",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0413"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0413",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0414"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0414",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0415"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0415",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0416"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0416",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0417"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0417",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0418"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0418",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0419"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0419",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0420"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0420",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0421"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0421",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0422"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0422",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0423"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0423",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0424"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0424",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0425"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0425",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0426"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0426",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0427"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0427",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0428"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0428",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0429"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0429",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0430"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0430",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0431"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0431",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0432"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0432",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0433"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0433",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0434"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0434",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0435"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0435",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0436"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0436",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0437"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0437",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0438"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0438",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0439"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0439",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0440"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0440",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0441"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0441",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0442"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0442",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0443"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0443",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0444"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0444",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0445"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0445",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0446"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0446",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0447"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0447",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0448"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0448",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["NTPSKEWDETECTOR-R-0449"] = NtpSkewDetectorRule(
            rule_id="NTPSKEWDETECTOR-R-0449",
            name="NTP Monlist Reflection & Timestamp Skew Detector Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: NtpSkewDetectorHeader) -> Dict[str, Any]:
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

ntp_monlist_amplification_instance = NtpSkewDetectorEngine()

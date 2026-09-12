"""
SentinelAI - Dynamic ARP Inspection & Gratuitous ARP Filter
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for ArpInspection.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class ArpInspectionState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class ArpInspectionHeader:
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
class ArpInspectionRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class ArpInspectionEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["ARPINSPECTION-R-0001"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0001",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0002"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0002",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0003"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0003",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0004"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0004",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0005"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0005",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0006"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0006",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0007"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0007",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0008"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0008",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0009"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0009",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0010"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0010",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0011"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0011",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0012"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0012",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0013"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0013",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0014"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0014",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0015"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0015",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0016"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0016",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0017"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0017",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0018"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0018",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0019"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0019",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0020"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0020",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0021"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0021",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0022"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0022",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0023"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0023",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0024"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0024",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0025"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0025",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0026"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0026",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0027"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0027",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0028"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0028",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0029"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0029",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0030"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0030",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0031"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0031",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0032"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0032",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0033"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0033",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0034"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0034",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0035"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0035",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0036"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0036",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0037"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0037",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0038"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0038",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0039"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0039",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0040"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0040",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0041"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0041",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0042"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0042",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0043"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0043",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0044"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0044",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0045"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0045",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0046"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0046",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0047"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0047",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0048"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0048",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0049"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0049",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0050"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0050",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0051"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0051",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0052"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0052",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0053"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0053",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0054"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0054",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0055"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0055",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0056"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0056",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0057"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0057",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0058"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0058",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0059"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0059",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0060"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0060",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0061"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0061",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0062"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0062",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0063"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0063",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0064"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0064",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0065"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0065",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0066"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0066",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0067"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0067",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0068"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0068",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0069"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0069",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0070"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0070",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0071"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0071",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0072"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0072",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0073"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0073",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0074"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0074",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0075"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0075",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0076"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0076",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0077"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0077",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0078"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0078",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0079"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0079",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0080"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0080",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0081"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0081",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0082"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0082",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0083"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0083",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0084"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0084",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0085"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0085",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0086"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0086",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0087"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0087",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0088"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0088",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0089"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0089",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0090"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0090",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0091"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0091",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0092"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0092",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0093"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0093",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0094"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0094",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0095"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0095",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0096"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0096",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0097"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0097",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0098"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0098",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0099"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0099",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0100"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0100",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0101"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0101",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0102"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0102",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0103"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0103",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0104"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0104",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0105"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0105",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0106"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0106",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0107"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0107",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0108"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0108",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0109"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0109",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0110"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0110",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0111"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0111",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0112"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0112",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0113"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0113",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0114"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0114",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0115"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0115",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0116"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0116",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0117"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0117",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0118"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0118",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0119"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0119",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0120"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0120",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0121"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0121",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0122"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0122",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0123"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0123",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0124"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0124",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0125"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0125",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0126"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0126",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0127"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0127",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0128"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0128",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0129"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0129",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0130"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0130",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0131"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0131",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0132"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0132",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0133"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0133",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0134"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0134",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0135"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0135",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0136"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0136",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0137"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0137",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0138"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0138",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0139"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0139",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0140"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0140",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0141"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0141",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0142"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0142",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0143"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0143",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0144"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0144",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0145"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0145",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0146"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0146",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0147"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0147",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0148"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0148",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0149"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0149",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0150"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0150",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0151"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0151",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0152"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0152",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0153"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0153",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0154"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0154",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0155"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0155",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0156"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0156",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0157"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0157",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0158"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0158",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0159"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0159",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0160"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0160",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0161"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0161",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0162"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0162",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0163"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0163",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0164"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0164",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0165"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0165",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0166"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0166",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0167"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0167",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0168"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0168",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0169"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0169",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0170"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0170",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0171"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0171",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0172"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0172",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0173"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0173",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0174"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0174",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0175"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0175",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0176"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0176",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0177"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0177",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0178"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0178",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0179"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0179",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0180"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0180",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0181"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0181",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0182"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0182",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0183"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0183",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0184"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0184",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0185"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0185",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0186"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0186",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0187"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0187",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0188"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0188",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0189"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0189",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0190"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0190",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0191"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0191",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0192"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0192",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0193"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0193",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0194"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0194",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0195"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0195",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0196"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0196",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0197"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0197",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0198"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0198",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0199"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0199",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0200"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0200",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0201"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0201",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0202"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0202",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0203"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0203",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0204"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0204",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0205"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0205",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0206"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0206",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0207"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0207",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0208"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0208",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0209"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0209",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0210"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0210",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0211"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0211",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0212"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0212",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0213"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0213",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0214"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0214",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0215"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0215",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0216"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0216",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0217"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0217",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0218"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0218",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0219"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0219",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0220"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0220",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0221"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0221",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0222"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0222",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0223"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0223",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0224"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0224",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0225"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0225",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0226"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0226",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0227"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0227",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0228"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0228",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0229"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0229",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0230"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0230",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0231"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0231",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0232"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0232",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0233"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0233",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0234"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0234",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0235"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0235",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0236"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0236",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0237"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0237",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0238"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0238",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0239"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0239",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0240"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0240",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0241"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0241",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0242"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0242",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0243"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0243",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0244"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0244",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0245"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0245",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0246"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0246",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0247"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0247",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0248"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0248",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0249"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0249",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0250"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0250",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0251"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0251",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0252"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0252",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0253"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0253",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0254"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0254",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0255"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0255",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0256"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0256",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0257"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0257",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0258"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0258",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0259"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0259",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0260"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0260",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0261"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0261",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0262"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0262",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0263"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0263",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0264"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0264",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0265"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0265",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0266"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0266",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0267"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0267",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0268"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0268",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0269"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0269",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0270"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0270",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0271"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0271",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0272"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0272",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0273"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0273",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0274"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0274",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0275"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0275",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0276"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0276",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0277"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0277",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0278"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0278",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0279"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0279",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0280"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0280",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0281"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0281",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0282"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0282",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0283"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0283",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0284"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0284",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0285"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0285",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0286"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0286",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0287"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0287",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0288"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0288",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0289"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0289",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0290"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0290",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0291"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0291",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0292"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0292",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0293"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0293",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0294"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0294",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0295"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0295",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0296"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0296",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0297"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0297",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0298"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0298",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0299"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0299",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0300"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0300",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0301"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0301",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0302"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0302",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0303"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0303",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0304"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0304",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0305"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0305",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0306"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0306",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0307"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0307",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0308"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0308",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0309"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0309",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0310"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0310",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0311"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0311",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0312"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0312",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0313"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0313",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0314"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0314",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0315"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0315",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0316"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0316",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0317"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0317",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0318"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0318",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0319"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0319",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0320"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0320",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0321"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0321",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0322"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0322",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0323"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0323",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0324"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0324",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0325"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0325",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0326"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0326",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0327"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0327",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0328"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0328",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0329"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0329",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0330"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0330",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0331"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0331",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0332"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0332",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0333"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0333",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0334"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0334",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0335"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0335",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0336"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0336",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0337"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0337",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0338"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0338",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0339"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0339",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0340"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0340",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0341"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0341",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0342"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0342",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0343"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0343",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0344"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0344",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0345"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0345",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0346"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0346",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0347"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0347",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0348"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0348",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0349"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0349",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0350"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0350",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0351"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0351",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0352"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0352",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0353"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0353",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0354"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0354",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0355"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0355",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0356"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0356",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0357"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0357",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0358"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0358",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0359"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0359",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0360"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0360",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0361"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0361",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0362"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0362",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0363"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0363",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0364"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0364",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0365"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0365",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0366"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0366",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0367"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0367",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0368"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0368",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0369"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0369",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0370"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0370",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0371"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0371",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0372"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0372",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0373"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0373",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0374"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0374",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0375"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0375",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0376"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0376",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0377"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0377",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0378"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0378",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0379"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0379",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0380"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0380",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0381"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0381",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0382"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0382",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0383"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0383",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0384"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0384",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0385"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0385",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0386"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0386",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0387"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0387",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0388"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0388",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0389"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0389",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0390"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0390",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0391"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0391",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0392"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0392",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0393"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0393",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0394"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0394",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0395"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0395",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0396"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0396",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0397"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0397",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0398"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0398",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0399"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0399",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0400"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0400",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0401"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0401",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0402"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0402",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0403"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0403",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0404"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0404",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0405"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0405",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0406"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0406",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0407"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0407",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0408"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0408",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0409"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0409",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0410"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0410",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0411"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0411",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0412"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0412",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0413"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0413",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0414"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0414",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0415"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0415",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0416"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0416",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0417"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0417",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0418"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0418",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0419"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0419",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0420"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0420",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0421"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0421",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0422"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0422",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0423"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0423",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0424"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0424",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0425"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0425",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0426"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0426",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0427"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0427",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0428"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0428",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0429"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0429",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0430"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0430",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0431"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0431",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0432"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0432",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0433"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0433",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0434"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0434",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0435"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0435",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0436"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0436",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0437"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0437",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0438"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0438",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0439"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0439",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0440"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0440",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0441"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0441",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0442"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0442",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0443"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0443",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0444"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0444",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0445"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0445",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0446"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0446",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0447"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0447",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0448"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0448",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["ARPINSPECTION-R-0449"] = ArpInspectionRule(
            rule_id="ARPINSPECTION-R-0449",
            name="Dynamic ARP Inspection & Gratuitous ARP Filter Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: ArpInspectionHeader) -> Dict[str, Any]:
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

arp_dynamic_inspection_instance = ArpInspectionEngine()

"""
SentinelAI - Cisco HSRP Standby Priority & State Flapping Monitor
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for HsrpMonitor.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class HsrpMonitorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class HsrpMonitorHeader:
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
class HsrpMonitorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class HsrpMonitorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["HSRPMONITOR-R-0001"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0001",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0002"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0002",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0003"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0003",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0004"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0004",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0005"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0005",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0006"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0006",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0007"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0007",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0008"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0008",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0009"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0009",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0010"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0010",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0011"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0011",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0012"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0012",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0013"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0013",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0014"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0014",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0015"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0015",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0016"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0016",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0017"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0017",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0018"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0018",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0019"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0019",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0020"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0020",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0021"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0021",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0022"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0022",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0023"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0023",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0024"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0024",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0025"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0025",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0026"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0026",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0027"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0027",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0028"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0028",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0029"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0029",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0030"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0030",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0031"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0031",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0032"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0032",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0033"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0033",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0034"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0034",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0035"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0035",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0036"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0036",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0037"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0037",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0038"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0038",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0039"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0039",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0040"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0040",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0041"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0041",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0042"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0042",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0043"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0043",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0044"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0044",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0045"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0045",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0046"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0046",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0047"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0047",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0048"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0048",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0049"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0049",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0050"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0050",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0051"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0051",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0052"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0052",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0053"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0053",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0054"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0054",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0055"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0055",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0056"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0056",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0057"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0057",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0058"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0058",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0059"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0059",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0060"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0060",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0061"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0061",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0062"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0062",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0063"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0063",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0064"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0064",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0065"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0065",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0066"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0066",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0067"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0067",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0068"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0068",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0069"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0069",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0070"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0070",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0071"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0071",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0072"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0072",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0073"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0073",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0074"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0074",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0075"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0075",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0076"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0076",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0077"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0077",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0078"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0078",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0079"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0079",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0080"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0080",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0081"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0081",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0082"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0082",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0083"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0083",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0084"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0084",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0085"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0085",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0086"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0086",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0087"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0087",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0088"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0088",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0089"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0089",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0090"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0090",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0091"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0091",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0092"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0092",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0093"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0093",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0094"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0094",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0095"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0095",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0096"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0096",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0097"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0097",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0098"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0098",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0099"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0099",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0100"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0100",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0101"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0101",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0102"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0102",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0103"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0103",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0104"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0104",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0105"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0105",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0106"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0106",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0107"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0107",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0108"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0108",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0109"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0109",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0110"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0110",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0111"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0111",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0112"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0112",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0113"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0113",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0114"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0114",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0115"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0115",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0116"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0116",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0117"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0117",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0118"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0118",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0119"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0119",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0120"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0120",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0121"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0121",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0122"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0122",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0123"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0123",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0124"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0124",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0125"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0125",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0126"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0126",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0127"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0127",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0128"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0128",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0129"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0129",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0130"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0130",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0131"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0131",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0132"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0132",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0133"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0133",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0134"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0134",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0135"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0135",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0136"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0136",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0137"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0137",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0138"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0138",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0139"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0139",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0140"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0140",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0141"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0141",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0142"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0142",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0143"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0143",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0144"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0144",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0145"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0145",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0146"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0146",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0147"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0147",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0148"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0148",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0149"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0149",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0150"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0150",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0151"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0151",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0152"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0152",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0153"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0153",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0154"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0154",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0155"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0155",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0156"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0156",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0157"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0157",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0158"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0158",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0159"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0159",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0160"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0160",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0161"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0161",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0162"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0162",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0163"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0163",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0164"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0164",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0165"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0165",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0166"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0166",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0167"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0167",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0168"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0168",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0169"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0169",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0170"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0170",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0171"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0171",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0172"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0172",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0173"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0173",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0174"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0174",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0175"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0175",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0176"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0176",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0177"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0177",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0178"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0178",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0179"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0179",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0180"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0180",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0181"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0181",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0182"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0182",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0183"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0183",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0184"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0184",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0185"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0185",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0186"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0186",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0187"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0187",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0188"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0188",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0189"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0189",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0190"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0190",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0191"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0191",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0192"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0192",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0193"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0193",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0194"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0194",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0195"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0195",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0196"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0196",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0197"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0197",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0198"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0198",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0199"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0199",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0200"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0200",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0201"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0201",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0202"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0202",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0203"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0203",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0204"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0204",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0205"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0205",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0206"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0206",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0207"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0207",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0208"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0208",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0209"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0209",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0210"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0210",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0211"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0211",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0212"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0212",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0213"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0213",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0214"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0214",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0215"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0215",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0216"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0216",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0217"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0217",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0218"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0218",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0219"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0219",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0220"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0220",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0221"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0221",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0222"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0222",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0223"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0223",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0224"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0224",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0225"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0225",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0226"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0226",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0227"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0227",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0228"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0228",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0229"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0229",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0230"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0230",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0231"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0231",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0232"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0232",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0233"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0233",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0234"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0234",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0235"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0235",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0236"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0236",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0237"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0237",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0238"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0238",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0239"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0239",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0240"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0240",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0241"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0241",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0242"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0242",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0243"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0243",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0244"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0244",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0245"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0245",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0246"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0246",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0247"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0247",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0248"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0248",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0249"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0249",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0250"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0250",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0251"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0251",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0252"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0252",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0253"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0253",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0254"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0254",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0255"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0255",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0256"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0256",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0257"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0257",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0258"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0258",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0259"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0259",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0260"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0260",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0261"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0261",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0262"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0262",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0263"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0263",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0264"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0264",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0265"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0265",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0266"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0266",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0267"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0267",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0268"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0268",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0269"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0269",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0270"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0270",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0271"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0271",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0272"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0272",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0273"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0273",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0274"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0274",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0275"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0275",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0276"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0276",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0277"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0277",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0278"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0278",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0279"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0279",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0280"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0280",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0281"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0281",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0282"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0282",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0283"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0283",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0284"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0284",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0285"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0285",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0286"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0286",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0287"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0287",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0288"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0288",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0289"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0289",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0290"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0290",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0291"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0291",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0292"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0292",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0293"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0293",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0294"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0294",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0295"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0295",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0296"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0296",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0297"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0297",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0298"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0298",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0299"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0299",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0300"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0300",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0301"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0301",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0302"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0302",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0303"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0303",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0304"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0304",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0305"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0305",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0306"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0306",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0307"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0307",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0308"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0308",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0309"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0309",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0310"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0310",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0311"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0311",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0312"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0312",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0313"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0313",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0314"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0314",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0315"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0315",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0316"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0316",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0317"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0317",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0318"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0318",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0319"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0319",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0320"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0320",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0321"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0321",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0322"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0322",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0323"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0323",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0324"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0324",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0325"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0325",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0326"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0326",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0327"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0327",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0328"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0328",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0329"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0329",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0330"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0330",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0331"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0331",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0332"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0332",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0333"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0333",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0334"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0334",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0335"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0335",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0336"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0336",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0337"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0337",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0338"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0338",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0339"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0339",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0340"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0340",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0341"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0341",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0342"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0342",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0343"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0343",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0344"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0344",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0345"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0345",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0346"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0346",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0347"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0347",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0348"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0348",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0349"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0349",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0350"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0350",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0351"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0351",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0352"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0352",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0353"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0353",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0354"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0354",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0355"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0355",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0356"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0356",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0357"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0357",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0358"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0358",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0359"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0359",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0360"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0360",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0361"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0361",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0362"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0362",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0363"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0363",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0364"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0364",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0365"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0365",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0366"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0366",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0367"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0367",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0368"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0368",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0369"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0369",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0370"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0370",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0371"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0371",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0372"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0372",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0373"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0373",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0374"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0374",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0375"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0375",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0376"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0376",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0377"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0377",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0378"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0378",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0379"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0379",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0380"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0380",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0381"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0381",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0382"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0382",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0383"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0383",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0384"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0384",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0385"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0385",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0386"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0386",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0387"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0387",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0388"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0388",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0389"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0389",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0390"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0390",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0391"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0391",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0392"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0392",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0393"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0393",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0394"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0394",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0395"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0395",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0396"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0396",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0397"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0397",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0398"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0398",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0399"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0399",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0400"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0400",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0401"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0401",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0402"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0402",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0403"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0403",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0404"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0404",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0405"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0405",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0406"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0406",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0407"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0407",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0408"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0408",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0409"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0409",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0410"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0410",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0411"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0411",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0412"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0412",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0413"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0413",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0414"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0414",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0415"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0415",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0416"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0416",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0417"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0417",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0418"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0418",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0419"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0419",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0420"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0420",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0421"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0421",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0422"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0422",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0423"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0423",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0424"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0424",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0425"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0425",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0426"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0426",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0427"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0427",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0428"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0428",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0429"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0429",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0430"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0430",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0431"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0431",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0432"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0432",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0433"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0433",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0434"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0434",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0435"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0435",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0436"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0436",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0437"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0437",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0438"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0438",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0439"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0439",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0440"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0440",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0441"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0441",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0442"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0442",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0443"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0443",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0444"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0444",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0445"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0445",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0446"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0446",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0447"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0447",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0448"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0448",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HSRPMONITOR-R-0449"] = HsrpMonitorRule(
            rule_id="HSRPMONITOR-R-0449",
            name="Cisco HSRP Standby Priority & State Flapping Monitor Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: HsrpMonitorHeader) -> Dict[str, Any]:
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

hsrp_cisco_priority_monitor_instance = HsrpMonitorEngine()

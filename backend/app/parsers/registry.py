"""Unified Parser Registry with heuristic format detection."""
import os
from typing import Dict
from .base_parser import BaseParser, ParserError
from .csv_parser import CSVParser
from .json_parser import JSONParser
from .syslog_parser import SyslogParser
from .cef_parser import CEFParser
from .windows_parser import WindowsEventParser
from .web_parser import WebServerParser
from .firewall_parser import FirewallParser
from .endpoint_parser import EndpointParser
from .windows_deep import WindowsDeepParser
from .nsm_parsers import ZeekNSMParser, SuricataEVEParser
from .cloud_linux_parsers import LinuxAuditdParser, CloudAuditParser

class ParserRegistry:
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {
            "csv": CSVParser(),
            "json": JSONParser(),
            "syslog": SyslogParser(),
            "cef": CEFParser(),
            "windows": WindowsDeepParser(),
            "windows_legacy": WindowsEventParser(),
            "web": WebServerParser(),
            "firewall": FirewallParser(),
            "endpoint": EndpointParser(),
            "zeek": ZeekNSMParser(),
            "suricata": SuricataEVEParser(),
            "auditd": LinuxAuditdParser(),
            "cloud": CloudAuditParser(),
        }

    def get_parser(self, format_name: str) -> BaseParser:
        parser = self._parsers.get(format_name.lower())
        if not parser:
            raise ParserError(f"Unknown log parser format '{format_name}'.")
        return parser

    def detect_and_get(self, filename: str, content_type: str | None = None, sample: bytes | None = None) -> tuple[str, BaseParser]:
        ext = os.path.splitext(filename.lower())[1]
        
        # Check by extension & contents
        if ext == ".csv" or content_type in {"text/csv", "application/csv"}:
            return "csv", self._parsers["csv"]
        if ext in {".json", ".jsonl", ".ndjson"} or content_type in {"application/json", "application/x-ndjson"}:
            if sample and (b"event_type" in sample or b"alert" in sample):
                return "suricata", self._parsers["suricata"]
            if sample and (b"_path" in sample or b"id.orig_h" in sample):
                return "zeek", self._parsers["zeek"]
            if sample and (b"eventSource" in sample or b"protoPayload" in sample):
                return "cloud", self._parsers["cloud"]
            return "json", self._parsers["json"]
        if "zeek" in filename.lower() or "conn.log" in filename.lower() or "dns.log" in filename.lower():
            return "zeek", self._parsers["zeek"]
        if "suricata" in filename.lower() or "eve.json" in filename.lower() or "fast.log" in filename.lower():
            return "suricata", self._parsers["suricata"]
        if "audit.log" in filename.lower() or "auditd" in filename.lower():
            return "auditd", self._parsers["auditd"]
        if "cloudtrail" in filename.lower() or "gcp" in filename.lower():
            return "cloud", self._parsers["cloud"]
        if ext in {".syslog", ".log"} or content_type in {"text/plain", "application/x-syslog"}:
            # Content sample heuristic
            if sample and b"CEF:" in sample[:200]:
                return "cef", self._parsers["cef"]
            if sample and (b"<Event" in sample[:200] or b"<Events" in sample[:200] or b"EventID" in sample[:200]):
                return "windows", self._parsers["windows"]
            if sample and b"type=SYSCALL" in sample[:200]:
                return "auditd", self._parsers["auditd"]
            return "syslog", self._parsers["syslog"]
        if ext == ".cef":
            return "cef", self._parsers["cef"]
        if ext in {".xml", ".evtx_xml"} or content_type in {"text/xml", "application/xml"}:
            return "windows", self._parsers["windows"]
        if "access" in filename.lower() or "http" in filename.lower():
            return "web", self._parsers["web"]
        if "fw" in filename.lower() or "firewall" in filename.lower() or "iptables" in filename.lower():
            return "firewall", self._parsers["firewall"]
        if "sysmon" in filename.lower() or "osquery" in filename.lower() or "edr" in filename.lower():
            return "windows", self._parsers["windows"]

        # Default fallback to syslog text parser
        return "syslog", self._parsers["syslog"]

registry = ParserRegistry()

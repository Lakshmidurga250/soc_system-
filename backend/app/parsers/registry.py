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

class ParserRegistry:
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {
            "csv": CSVParser(),
            "json": JSONParser(),
            "syslog": SyslogParser(),
            "cef": CEFParser(),
            "windows": WindowsEventParser(),
            "web": WebServerParser(),
            "firewall": FirewallParser(),
            "endpoint": EndpointParser(),
        }

    def get_parser(self, format_name: str) -> BaseParser:
        parser = self._parsers.get(format_name.lower())
        if not parser:
            raise ParserError(f"Unknown log parser format '{format_name}'.")
        return parser

    def detect_and_get(self, filename: str, content_type: str | None = None, sample: bytes | None = None) -> tuple[str, BaseParser]:
        ext = os.path.splitext(filename.lower())[1]
        
        # Check by extension
        if ext == ".csv" or content_type in {"text/csv", "application/csv"}:
            return "csv", self._parsers["csv"]
        if ext in {".json", ".jsonl", ".ndjson"} or content_type in {"application/json", "application/x-ndjson"}:
            return "json", self._parsers["json"]
        if ext in {".syslog", ".log"} or content_type in {"text/plain", "application/x-syslog"}:
            # Content sample heuristic
            if sample and b"CEF:" in sample[:200]:
                return "cef", self._parsers["cef"]
            if sample and (b"<Event" in sample[:200] or b"<Events" in sample[:200]):
                return "windows", self._parsers["windows"]
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
            return "endpoint", self._parsers["endpoint"]

        # Default fallback to syslog text parser
        return "syslog", self._parsers["syslog"]

registry = ParserRegistry()

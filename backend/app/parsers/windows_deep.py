"""Comprehensive Windows Event ID & Sysmon Deep Telemetry Parser for SentinelAI."""
from typing import Dict, Any, List, Optional
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from .base_parser import BaseParser

class WindowsDeepParser(BaseParser):
    """Deep parser for Windows Security Events & Microsoft Sysmon Telemetry."""

    SUPPORTED_SECURITY_EVENTS = {
        "4624": {"category": "Authentication", "action": "Successful Logon", "severity": "LOW"},
        "4625": {"category": "Authentication", "action": "Failed Logon Attempt", "severity": "HIGH"},
        "4672": {"category": "Privilege", "action": "Special Privileges Assigned", "severity": "MEDIUM"},
        "4688": {"category": "Process Creation", "action": "New Process Created", "severity": "MEDIUM"},
        "4697": {"category": "Persistence", "action": "Service Installed in System", "severity": "HIGH"},
        "4720": {"category": "Account Management", "action": "User Account Created", "severity": "MEDIUM"},
        "4728": {"category": "Group Management", "action": "Member Added to Security Group", "severity": "HIGH"},
        "4738": {"category": "Account Management", "action": "User Account Modified", "severity": "MEDIUM"},
        "7045": {"category": "System Service", "action": "New Service Installed (System Log)", "severity": "HIGH"},
        "1102": {"category": "Defense Evasion", "action": "Audit Log Cleared by User", "severity": "CRITICAL"},
        "4104": {"category": "Execution", "action": "PowerShell Script Block Execution", "severity": "HIGH"},
    }

    SUPPORTED_SYSMON_EVENTS = {
        "1": {"category": "Sysmon Process", "action": "Process Create", "severity": "MEDIUM"},
        "3": {"category": "Sysmon Network", "action": "Network Connection Initiated", "severity": "LOW"},
        "7": {"category": "Sysmon Module", "action": "Image / DLL Loaded", "severity": "LOW"},
        "8": {"category": "Sysmon Injection", "action": "CreateRemoteThread Detected", "severity": "CRITICAL"},
        "10": {"category": "Sysmon Memory", "action": "Process Access / LSASS Read", "severity": "HIGH"},
        "11": {"category": "Sysmon File", "action": "File Created", "severity": "LOW"},
        "12": {"category": "Sysmon Registry", "action": "Registry Object Created/Deleted", "severity": "MEDIUM"},
        "13": {"category": "Sysmon Registry", "action": "Registry Value Set", "severity": "MEDIUM"},
        "22": {"category": "Sysmon DNS", "action": "DNS Query Requested", "severity": "LOW"},
    }

    def can_parse(self, content: str) -> bool:
        """Check if content matches Windows XML or structured Windows Security / Sysmon event."""
        if "<Event " in content or "<EventID>" in content or "EventID" in content:
            return True
        if "Microsoft-Windows-Sysmon" in content or "Microsoft-Windows-Security-Auditing" in content:
            return True
        if re.search(r"EventID[=:\s]+(\d+)", content, re.IGNORECASE):
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse raw Windows / Sysmon content into canonical normalized telemetry structures."""
        results: List[Dict[str, Any]] = []
        if "<Event " in content or "<Events>" in content:
            results.extend(self._parse_xml_events(content))
        else:
            for line in content.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed = self._parse_single_text_event(line)
                if parsed:
                    results.append(parsed)
        return results

    def _parse_xml_events(self, xml_content: str) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        clean_xml = xml_content.strip()
        # Strip xmlns attributes to make tag finding completely agnostic to namespace variations
        clean_xml = re.sub(r'\sxmlns(:\w+)?="[^"]+"', '', clean_xml)
        
        if not clean_xml.startswith("<Events>") and not clean_xml.startswith("<Event"):
            clean_xml = f"<Events>{clean_xml}</Events>"
        elif clean_xml.startswith("<Event"):
            clean_xml = f"<Events>{clean_xml}</Events>"

        try:
            root = ET.fromstring(clean_xml)
            event_nodes = [e for e in root.iter() if e.tag.endswith("Event") and e != root]
            if not event_nodes and root.tag.endswith("Event"):
                event_nodes = [root]
            for event_el in event_nodes:
                parsed = self._extract_xml_node(event_el)
                if parsed:
                    events.append(parsed)
        except Exception:
            # Fallback regex extraction for slightly malformed XML
            matches = re.findall(r"(<Event\b[^>]*>.*?</Event>)", clean_xml, re.DOTALL)
            for match in matches:
                try:
                    el = ET.fromstring(match)
                    parsed = self._extract_xml_node(el)
                    if parsed:
                        events.append(parsed)
                except Exception:
                    pass
        return events

    def _extract_xml_node(self, el: ET.Element) -> Optional[Dict[str, Any]]:
        event_id = ""
        provider = ""
        timestamp = datetime.now(timezone.utc).isoformat()
        channel = ""
        computer = "windows-host"

        # System Header
        system_el = None
        for child in el:
            if child.tag.endswith("System"):
                system_el = child
                break
        if system_el is not None:
            for node in system_el:
                tag = node.tag.split("}")[-1]
                if tag == "EventID":
                    event_id = node.text.strip() if node.text else ""
                elif tag == "Provider":
                    provider = node.attrib.get("Name", "")
                elif tag == "TimeCreated":
                    timestamp = node.attrib.get("SystemTime", timestamp)
                elif tag == "Computer":
                    computer = node.text.strip() if node.text else computer
                elif tag == "Channel":
                    channel = node.text.strip() if node.text else ""

        # EventData Fields
        event_data: Dict[str, str] = {}
        data_parent = None
        for child in el:
            if child.tag.endswith("EventData"):
                data_parent = child
                break
        if data_parent is not None:
            for data_node in data_parent:
                if data_node.tag.endswith("Data"):
                    name = data_node.attrib.get("Name")
                    val = data_node.text or ""
                    if name:
                        event_data[name] = val


        meta = self.SUPPORTED_SYSMON_EVENTS.get(event_id) or self.SUPPORTED_SECURITY_EVENTS.get(event_id, {
            "category": "Windows Telemetry",
            "action": f"Windows Event {event_id}",
            "severity": "LOW"
        })

        # Canonical normalization
        source_ip = event_data.get("IpAddress") or event_data.get("SourceIp") or event_data.get("DestinationIp") or "127.0.0.1"
        if source_ip in ["-", "::1"]:
            source_ip = "127.0.0.1"
        username = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or event_data.get("User") or "SYSTEM"
        process_name = event_data.get("Image") or event_data.get("NewProcessName") or event_data.get("ProcessName") or ""
        command_line = event_data.get("CommandLine") or event_data.get("ScriptBlockText") or ""

        return {
            "timestamp": timestamp,
            "event_id": event_id,
            "source": f"windows_{provider.lower() or 'security'}",
            "source_ip": source_ip,
            "destination_ip": event_data.get("DestinationIp") or "10.0.0.1",
            "port": int(event_data.get("DestinationPort", 0)) if str(event_data.get("DestinationPort", "")).isdigit() else None,
            "protocol": event_data.get("Protocol", "TCP"),
            "username": username,
            "hostname": computer,
            "event_type": f"WINDOWS_{event_id}_{meta['action'].replace(' ', '_').upper()}",
            "category": meta["category"],
            "action": meta["action"],
            "severity": meta["severity"],

            "status": "FAILURE" if event_id == "4625" else "SUCCESS",
            "resource": process_name or command_line[:120] or event_data.get("TargetFilename") or channel,
            "raw_message": ET.tostring(el, encoding="unicode"),
            "metadata_json": {
                "event_id": event_id,
                "provider": provider,
                "channel": channel,
                "command_line": command_line,
                "process_name": process_name,
                "parent_process": event_data.get("ParentImage", ""),
                "hashes": event_data.get("Hashes", ""),
                "event_data": event_data
            }
        }

    def _parse_single_text_event(self, line: str) -> Optional[Dict[str, Any]]:
        id_match = re.search(r"EventID[=:\s]+(\d+)", line, re.IGNORECASE)
        event_id = id_match.group(1) if id_match else "4624"
        meta = self.SUPPORTED_SYSMON_EVENTS.get(event_id) or self.SUPPORTED_SECURITY_EVENTS.get(event_id, {
            "category": "Windows Telemetry", "action": f"Event {event_id}", "severity": "LOW"
        })

        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        source_ip = ip_match.group(0) if ip_match else "127.0.0.1"

        user_match = re.search(r"Account Name:\s*([^\s,]+)|User:\s*([^\s,]+)", line, re.IGNORECASE)
        user = user_match.group(1) or user_match.group(2) if user_match else "SYSTEM"

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "windows_event_log",
            "source_ip": source_ip,
            "destination_ip": "10.0.0.1",
            "username": user,
            "hostname": "win-endpoint-01",
            "event_type": f"WINDOWS_{event_id}_{meta['action'].replace(' ', '_').upper()}",
            "category": meta["category"],
            "action": meta["action"],
            "severity": meta["severity"],
            "status": "FAILURE" if event_id == "4625" else "SUCCESS",
            "resource": f"Event ID {event_id}",
            "raw_message": line,
            "metadata_json": {"event_id": event_id, "parsed_format": "text_kv"}
        }

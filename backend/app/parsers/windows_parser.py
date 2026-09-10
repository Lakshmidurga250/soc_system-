import xml.etree.ElementTree as ET
import re
from .base_parser import BaseParser, ParsedRecord, ParserError

class WindowsEventParser(BaseParser):
    supported_extensions = (".xml", ".evtx_xml")

    def parse(self, payload: bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = payload.decode("latin-1")
            except UnicodeDecodeError as exc:
                raise ParserError("Windows XML is not valid text") from exc

        clean_text = text.strip()
        if not clean_text.startswith("<Events") and clean_text.count("<Event") > 1:
            clean_text = f"<Events>{clean_text}</Events>"
        elif not clean_text.startswith("<Events") and not clean_text.startswith("<Event"):
            clean_text = f"<Events>{clean_text}</Events>"

        try:
            root = ET.fromstring(clean_text)
        except ET.ParseError:
            return self._regex_fallback_parse(clean_text)

        event_nodes = [
            elem for elem in root.iter()
            if elem.tag.split("}")[-1] == "Event"
        ]
        if not event_nodes:
            raise ParserError("No <Event> nodes found in Windows XML payload")

        for index, node in enumerate(event_nodes, start=1):
            record = self._extract_event_node(node)
            yield ParsedRecord(record, index)

    def _extract_event_node(self, node: ET.Element) -> dict:
        event_id = None
        computer = None
        time_created = None
        data_dict = {}

        for elem in node.iter():
            tag = elem.tag.split("}")[-1]
            if tag == "EventID":
                event_id = elem.text
            elif tag == "Computer":
                computer = elem.text
            elif tag == "TimeCreated":
                time_created = elem.attrib.get("SystemTime")
            elif tag == "Data":
                name = elem.attrib.get("Name")
                if name:
                    data_dict[name] = elem.text

        event_id_str = event_id or "0"
        status = "FAILURE" if event_id_str in ("4625", "4771", "4776") else "SUCCESS"
        severity = "HIGH" if event_id_str in ("4625", "4720", "4672") else "LOW"

        return {
            "source": "windows_events",
            "event_type": f"WinEvent_{event_id_str}",
            "timestamp": time_created,
            "hostname": computer or data_dict.get("WorkstationName"),
            "username": data_dict.get("TargetUserName") or data_dict.get("SubjectUserName") or data_dict.get("UserName"),
            "source_ip": data_dict.get("IpAddress") or data_dict.get("SourceNetworkAddress"),
            "port": int(data_dict.get("IpPort")) if data_dict.get("IpPort") and data_dict.get("IpPort").isdigit() else None,
            "status": status,
            "severity": severity,
            "resource": data_dict.get("ProcessName") or data_dict.get("NewProcessName") or data_dict.get("ServiceName"),
            "raw_message": f"Windows EventID {event_id_str} on {computer or 'host'}: User={data_dict.get('TargetUserName', 'N/A')}",
        }

    def _regex_fallback_parse(self, text: str):
        event_chunks = re.split(r"(?=<Event[\s>])", text)
        valid_chunks = [c for c in event_chunks if "<Event" in c]
        if not valid_chunks:
            raise ParserError("Could not parse Windows Event XML")
        for idx, chunk in enumerate(valid_chunks, start=1):
            try:
                elem = ET.fromstring(chunk.strip())
                yield ParsedRecord(self._extract_event_node(elem), idx)
            except Exception:
                continue

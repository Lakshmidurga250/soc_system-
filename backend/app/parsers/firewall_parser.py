"""Firewall and Network Perimeter Log Parser."""
import re
from .base_parser import BaseParser, ParsedRecord, ParserError

# NetFilter / Iptables log format: [timestamp] IN=eth0 OUT= MAC=... SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=44321 DPT=22
IPTABLES_RE = re.compile(r'SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).+PROTO=(?P<proto>\S+)\s+SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+)')

class FirewallParser(BaseParser):
    supported_extensions = (".firewall", ".fw.log", ".iptables")

    def parse(self, payload: bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = payload.decode("latin-1", errors="replace")

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ParserError("Firewall log file is empty")

        for index, line in enumerate(lines, start=1):
            m = IPTABLES_RE.search(line)
            action = "DROP" if any(w in line.upper() for w in ("DROP", "DENY", "BLOCK", "REJECT")) else "ACCEPT"
            is_blocked = action != "ACCEPT"

            if m:
                d = m.groupdict()
                dest_port = int(d.get("dpt") or 0)
                is_sensitive_port = dest_port in (22, 3389, 445, 1433, 3306, 23)

                record = {
                    "source": "firewall",
                    "source_ip": d.get("src"),
                    "destination_ip": d.get("dst"),
                    "event_type": f"firewall_{action.lower()}",
                    "category": "network",
                    "action": action,
                    "status": "FAILURE" if is_blocked else "SUCCESS",
                    "protocol": d.get("proto"),
                    "port": dest_port,
                    "severity": "HIGH" if is_blocked and is_sensitive_port else "MEDIUM" if is_blocked else "LOW",
                    "raw_message": line,
                }
                yield ParsedRecord(record, index)
            else:
                yield ParsedRecord({
                    "source": "firewall",
                    "event_type": "firewall_event",
                    "category": "network",
                    "raw_message": line,
                    "severity": "LOW",
                    "status": "SUCCESS",
                }, index)

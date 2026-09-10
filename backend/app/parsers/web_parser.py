"""Web Server Log Parser for Nginx, Apache, and W3C formats."""
import re
from .base_parser import BaseParser, ParsedRecord, ParserError

# Combined log format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

class WebServerParser(BaseParser):
    supported_extensions = (".access.log", ".http.log", ".web.log")

    def parse(self, payload: bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = payload.decode("latin-1", errors="replace")

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ParserError("Web server log is empty")

        for index, line in enumerate(lines, start=1):
            m = COMBINED_LOG_RE.match(line)
            if m:
                d = m.groupdict()
                status_code = int(d.get("status") or 200)
                is_err = status_code >= 400
                is_crit = status_code in (401, 403, 500) and any(kw in (d.get("path") or "") for kw in ("/admin", "/etc/passwd", "/.env", "/wp-login", "UNION", "SELECT"))

                record = {
                    "source": "web_server",
                    "source_ip": d.get("ip"),
                    "username": None if d.get("user") == "-" else d.get("user"),
                    "event_type": f"http_{d.get('method', 'GET').lower()}",
                    "category": "web",
                    "action": d.get("method"),
                    "status": "FAILURE" if is_err else "SUCCESS",
                    "resource": d.get("path"),
                    "protocol": d.get("proto"),
                    "user_agent": d.get("agent"),
                    "severity": "CRITICAL" if is_crit else "HIGH" if status_code == 403 else "MEDIUM" if is_err else "LOW",
                    "raw_message": line,
                }
                yield ParsedRecord(record, index)
            else:
                yield ParsedRecord({
                    "source": "web_server",
                    "event_type": "http_request",
                    "raw_message": line,
                    "status": "SUCCESS",
                    "severity": "LOW",
                }, index)

import re
from .base_parser import BaseParser, ParsedRecord, ParserError

# RFC 3164 regex: <34>Oct 11 22:14:15 myhost myproc[123]: msg
RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# RFC 5424 regex: <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] msg
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured_data>-|\[.*?\])?\s*(?P<message>.*)$"
)

# IP regex pattern helper
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
USER_RE = re.compile(r"\buser(?:name)?[:= ]+([a-zA-Z0-9_\.\-]+)\b", re.IGNORECASE)

class SyslogParser(BaseParser):
    supported_extensions = (".syslog", ".log")

    def parse(self, payload: bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = payload.decode("latin-1")
            except UnicodeDecodeError as exc:
                raise ParserError("Syslog payload is not valid text") from exc

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ParserError("Syslog log file is empty")

        for index, line in enumerate(lines, start=1):
            record: dict = {"raw_message": line, "source": "syslog"}
            m5424 = RFC5424_RE.match(line)
            m3164 = RFC3164_RE.match(line)

            if m5424:
                d = m5424.groupdict()
                record.update({
                    "timestamp": d.get("timestamp"),
                    "hostname": d.get("hostname"),
                    "event_type": d.get("app_name") or "syslog",
                    "raw_message": d.get("message") or line,
                })
            elif m3164:
                d = m3164.groupdict()
                record.update({
                    "timestamp": d.get("timestamp"),
                    "hostname": d.get("hostname"),
                    "event_type": d.get("tag") or "syslog",
                    "raw_message": d.get("message") or line,
                })
            else:
                record["event_type"] = "syslog"

            # Heuristic extraction of IP & User from raw syslog text
            ips = IP_RE.findall(line)
            if ips:
                record["source_ip"] = ips[0]
                if len(ips) > 1:
                    record["destination_ip"] = ips[1]

            user_match = USER_RE.search(line)
            if user_match:
                record["username"] = user_match.group(1)

            if "failed" in line.lower() or "denied" in line.lower() or "error" in line.lower():
                record["status"] = "FAILURE"
                record["severity"] = "HIGH" if "root" in line.lower() or "admin" in line.lower() else "MEDIUM"
            elif "accepted" in line.lower() or "success" in line.lower():
                record["status"] = "SUCCESS"
                record["severity"] = "LOW"

            yield ParsedRecord(record, index)

"""Endpoint EDR and Process Execution Telemetry Parser."""
import json
import re
from .base_parser import BaseParser, ParsedRecord, ParserError

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "whoami.exe", "net.exe", "vssadmin.exe",
    "mimikatz.exe", "rundll32.exe", "certutil.exe", "psexec.exe", "nc", "ncat", "bash"
}

class EndpointParser(BaseParser):
    supported_extensions = (".edr", ".sysmon", ".osquery")

    def parse(self, payload: bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = payload.decode("latin-1", errors="replace")

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ParserError("Endpoint log file is empty")

        for index, line in enumerate(lines, start=1):
            record = {
                "source": "endpoint_edr",
                "category": "process_execution",
                "raw_message": line,
            }

            # Try JSON format (Osquery / Sysmon JSON)
            if line.startswith("{") and line.endswith("}"):
                try:
                    data = json.loads(line)
                    proc = str(data.get("process_name") or data.get("name") or data.get("Image") or "unknown").lower()
                    user = str(data.get("username") or data.get("User") or "")
                    host = str(data.get("hostname") or data.get("hostIdentifier") or data.get("Computer") or "")
                    cmd = str(data.get("cmdline") or data.get("CommandLine") or "")

                    is_suspicious = any(sp in proc for sp in SUSPICIOUS_PROCESSES) or any(k in cmd.lower() for k in ("-enc", "downloadstring", "bypass", "invoke-expression", "lsass", "shadowcopy"))

                    record.update({
                        "event_type": "process_spawn",
                        "username": user or None,
                        "hostname": host or None,
                        "resource": proc,
                        "action": "execute",
                        "severity": "CRITICAL" if is_suspicious else "LOW",
                        "status": "SUCCESS",
                        "metadata_json": {"cmdline": cmd},
                    })
                    yield ParsedRecord(record, index)
                    continue
                except json.JSONDecodeError:
                    pass

            # Plaintext fallback
            is_suspicious = any(sp in line.lower() for sp in SUSPICIOUS_PROCESSES)
            record.update({
                "event_type": "process_activity",
                "severity": "HIGH" if is_suspicious else "LOW",
                "status": "SUCCESS",
            })
            yield ParsedRecord(record, index)

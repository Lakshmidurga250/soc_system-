"""Canonical Normalization Engine for SentinelAI.

Transforms raw parsed records from diverse log formats into canonical SecurityEvent schema.
"""
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict
from ..parsers.base_parser import ParsedRecord

IP_V4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def normalize_ip(ip_str: Any) -> str | None:
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        return None

def normalize_timestamp(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo:
            return ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    if isinstance(ts, str) and ts.strip():
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
        ):
            try:
                dt = datetime.strptime(ts.strip(), fmt)
                if dt.tzinfo:
                    return dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except ValueError:
                continue
    return datetime.now(timezone.utc).replace(tzinfo=None)

def normalize_severity(sev: Any) -> str:
    s = str(sev or "LOW").upper().strip()
    if s in ("CRITICAL", "CRIT", "EMERG", "ALERT", "FATAL", "5"):
        return "CRITICAL"
    if s in ("HIGH", "ERR", "ERROR", "4"):
        return "HIGH"
    if s in ("MEDIUM", "WARN", "WARNING", "3"):
        return "MEDIUM"
    if s in ("LOW", "NOTICE", "INFO", "INFORMATIONAL", "DEBUG", "1", "2"):
        return "LOW"
    return "LOW"

def normalize_status(status_str: Any) -> str:
    s = str(status_str or "SUCCESS").upper().strip()
    if any(w in s for w in ("FAIL", "DENY", "BLOCK", "DROP", "REJECT", "ERR", "401", "403", "500")):
        return "FAILURE"
    return "SUCCESS"

class NormalizationEngine:
    def normalize_record(self, record: ParsedRecord, source_format: str) -> Dict[str, Any]:
        val = record.values
        
        # Field aliases resolution
        source_ip = normalize_ip(
            val.get("source_ip") or val.get("src_ip") or val.get("src") or val.get("client_ip") or val.get("ip")
        )
        dest_ip = normalize_ip(
            val.get("destination_ip") or val.get("dst_ip") or val.get("dst") or val.get("server_ip")
        )
        username = val.get("username") or val.get("user") or val.get("suser") or val.get("account") or val.get("TargetUserName")
        if username:
            username = str(username).strip()
            if username in ("-", "unknown", "N/A"):
                username = None

        hostname = val.get("hostname") or val.get("host") or val.get("Computer") or val.get("shost")
        if hostname:
            hostname = str(hostname).strip()

        event_type = str(val.get("event_type") or val.get("action") or val.get("name") or "security_event").lower().strip()
        category = str(val.get("category") or "authentication").lower().strip()
        severity = normalize_severity(val.get("severity"))
        status = normalize_status(val.get("status") or val.get("action") or val.get("status_code"))

        raw_msg = str(val.get("raw_message") or val.get("message") or f"{event_type} on {hostname or 'system'}")

        return {
            "timestamp": normalize_timestamp(val.get("timestamp")),
            "source": source_format,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "username": username,
            "hostname": hostname,
            "event_type": event_type,
            "category": category,
            "action": val.get("action") or event_type,
            "status": status,
            "resource": str(val.get("resource") or val.get("path") or val.get("process") or "") or None,
            "protocol": str(val.get("protocol") or "TCP").upper(),
            "port": int(val.get("port")) if str(val.get("port", "")).isdigit() else None,
            "user_agent": str(val.get("user_agent") or "") or None,
            "severity": severity,
            "raw_message": raw_msg,
            "metadata_json": val.get("metadata_json") or {"parsed_row": record.row_number},
            "synthetic": bool(val.get("synthetic", False)),
        }

normalization_engine = NormalizationEngine()

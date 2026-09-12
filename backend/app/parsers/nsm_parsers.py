"""Network Security Monitoring (NSM) Parsers for Zeek/Bro and Suricata/Snort."""
from typing import Dict, Any, List, Optional
import json
import re
from datetime import datetime, timezone
from .base_parser import BaseParser

class ZeekNSMParser(BaseParser):
    """Deep parser for Zeek/Bro TSV and JSON formatted network telemetry logs."""

    def can_parse(self, content: str) -> bool:
        first_line = content.strip().splitlines()[0] if content.strip().splitlines() else ""
        if "#separator" in content or "#fields" in content or "#types" in content:
            return True
        if '"_path"' in content or '"id.orig_h"' in content or '"id.resp_h"' in content:
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        lines = content.strip().splitlines()
        
        # Check if JSON format
        if lines and lines[0].strip().startswith("{"):
            for line in lines:
                try:
                    obj = json.loads(line)
                    results.append(self._normalize_zeek_json(obj))
                except Exception:
                    pass
            return results

        # TSV format with #fields header
        field_names: List[str] = []
        log_type = "conn"
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#path"):
                parts = line.split()
                if len(parts) > 1:
                    log_type = parts[1]
            elif line.startswith("#fields"):
                field_names = line.split()[1:]
            elif line.startswith("#"):
                continue
            elif field_names:
                parts = line.split("\t") if "\t" in line else line.split()
                if len(parts) >= len(field_names):
                    record = dict(zip(field_names, parts[:len(field_names)]))
                    results.append(self._normalize_zeek_record(record, log_type, line))
        return results

    def _normalize_zeek_record(self, r: Dict[str, str], log_type: str, raw: str) -> Dict[str, Any]:
        ts_val = r.get("ts", "")
        dt_str = datetime.now(timezone.utc).isoformat()
        try:
            if ts_val and ts_val != "-":
                dt_str = datetime.fromtimestamp(float(ts_val), tz=timezone.utc).isoformat()
        except Exception:
            pass

        src_ip = r.get("id.orig_h") or r.get("orig_h") or "10.0.0.10"
        dst_ip = r.get("id.resp_h") or r.get("resp_h") or "192.168.1.1"
        dst_p = r.get("id.resp_p") or r.get("resp_p") or "80"
        proto = (r.get("proto") or "TCP").upper()
        service = r.get("service") or log_type

        return {
            "timestamp": dt_str,
            "source": f"zeek_{log_type}",
            "source_ip": src_ip if src_ip != "-" else "10.0.0.10",
            "destination_ip": dst_ip if dst_ip != "-" else "192.168.1.1",
            "port": int(dst_p) if dst_p.isdigit() else 80,
            "protocol": proto,
            "username": r.get("username") or r.get("user") or "network",
            "hostname": r.get("host") or r.get("query") or "zeek-sensor-01",
            "event_type": f"ZEEK_{log_type.upper()}_CONNECTION",
            "category": "Network Traffic",
            "action": f"Zeek {log_type.upper()} Observed",
            "severity": "MEDIUM" if r.get("conn_state") in ["S0", "REJ", "RSTOS0"] else "LOW",
            "status": "REJECTED" if r.get("conn_state") == "REJ" else "ESTABLISHED",
            "resource": r.get("query") or r.get("uri") or f"{dst_ip}:{dst_p}",
            "raw_message": raw,
            "metadata_json": {"zeek_type": log_type, "fields": r}
        }

    def _normalize_zeek_json(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        path = obj.get("_path") or obj.get("service") or "conn"
        src_ip = obj.get("id.orig_h") or obj.get("id", {}).get("orig_h", "10.0.0.10")
        dst_ip = obj.get("id.resp_h") or obj.get("id", {}).get("resp_h", "192.168.1.1")
        dst_p = obj.get("id.resp_p") or obj.get("id", {}).get("resp_p", 80)
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": f"zeek_{path}",
            "source_ip": str(src_ip),
            "destination_ip": str(dst_ip),
            "port": int(dst_p) if str(dst_p).isdigit() else 80,
            "protocol": (obj.get("proto") or "TCP").upper(),
            "username": "network",
            "hostname": obj.get("host") or obj.get("query") or "zeek-sensor",
            "event_type": f"ZEEK_{path.upper()}_TELEMETRY",
            "dns_query": obj.get("query"),
            "category": "Network Monitoring",
            "action": f"Zeek {path} Logged",
            "severity": "LOW",
            "status": "SUCCESS",
            "resource": obj.get("query") or obj.get("uri") or str(dst_ip),
            "raw_message": json.dumps(obj),
            "metadata_json": obj
        }



class SuricataEVEParser(BaseParser):
    """Deep parser for Suricata EVE JSON IDS/IPS alerts and network flow events."""

    def can_parse(self, content: str) -> bool:
        if '"event_type":' in content and ('"suricata"' in content or '"alert":' in content or '"flow":' in content):
            return True
        if re.search(r"\[\*\*\]\s+\[\d+:\d+:\d+\]", content): # Snort/Suricata fast.log
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for line in content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    results.append(self._normalize_eve_json(obj, line))
                except Exception:
                    pass
            elif "[**]" in line:
                parsed = self._normalize_fast_log(line)
                if parsed:
                    results.append(parsed)
        return results

    def _normalize_eve_json(self, obj: Dict[str, Any], raw: str) -> Dict[str, Any]:
        eve_type = obj.get("event_type", "alert")
        alert_info = obj.get("alert", {})
        severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        sev_num = alert_info.get("severity", 3)
        severity = severity_map.get(sev_num, "MEDIUM")

        signature = alert_info.get("signature") or f"Suricata {eve_type.upper()}"
        category = alert_info.get("category") or "Network IDS Alert"

        return {
            "timestamp": obj.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source": "suricata_eve_ids",
            "source_ip": obj.get("src_ip") or "192.168.1.100",
            "destination_ip": obj.get("dest_ip") or "10.0.0.5",
            "port": int(obj.get("dest_port", 0)) if str(obj.get("dest_port", "")).isdigit() else None,
            "protocol": (obj.get("proto") or "TCP").upper(),
            "username": "nids",
            "hostname": obj.get("host") or "suricata-sensor",
            "event_type": f"SURICATA_IDS_{signature.replace(' ', '_').upper()[:48]}",
            "category": category,
            "action": signature,
            "severity": severity,
            "status": "BLOCKED" if alert_info.get("action") == "blocked" else "DETECTED",
            "resource": f"SID:{alert_info.get('signature_id', 0)}",
            "raw_message": raw,
            "metadata_json": {
                "signature_id": alert_info.get("signature_id"),
                "rev": alert_info.get("rev"),
                "payload_printable": obj.get("payload_printable", ""),
                "http": obj.get("http", {}),
                "tls": obj.get("tls", {})
            }
        }

    def _normalize_fast_log(self, line: str) -> Optional[Dict[str, Any]]:
        # Format: 09/12-10:00:00.000000 [**] [1:2001219:19] ET MALWARE Suspicious [**] [Classification: ...] [Priority: 1] {TCP} 192.168.1.50:443 -> 10.0.0.1:80
        sig_match = re.search(r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+([^\[\*]+)\s+\[\*\*\]", line)
        signature = sig_match.group(1).strip() if sig_match else "Suricata Signature Alert"

        ip_match = re.search(r"\{(\w+)\}\s+([\d\.]+):?(\d+)?\s+->\s+([\d\.]+):?(\d+)?", line)
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        proto = "TCP"
        dst_port = 80
        if ip_match:
            proto = ip_match.group(1)
            src_ip = ip_match.group(2)
            dst_ip = ip_match.group(4)
            if ip_match.group(5):
                dst_port = int(ip_match.group(5))

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "suricata_fast_log",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": dst_port,
            "protocol": proto,
            "username": "nids",
            "hostname": "suricata-edge",
            "event_type": "SURICATA_FAST_ALERT",
            "category": "Network Intrusion Detection",
            "action": signature,
            "severity": "HIGH",
            "status": "DETECTED",
            "resource": signature,
            "raw_message": line,
            "metadata_json": {"signature": signature}
        }

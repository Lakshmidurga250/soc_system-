"""Linux Auditd and Cloud Infrastructure Audit Log Parsers."""
from typing import Dict, Any, List, Optional
import json
import re
from datetime import datetime, timezone
from .base_parser import BaseParser

class LinuxAuditdParser(BaseParser):
    """Parser for Linux Kernel Audit daemon logs (auditd / audit.log)."""

    def can_parse(self, content: str) -> bool:
        if "type=SYSCALL" in content or "type=EXECVE" in content or "type=USER_LOGIN" in content or "type=AVC" in content:
            return True
        if "audit(" in content and "msg=audit(" in content:
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for line in content.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("type="):
                continue
            parsed = self._parse_audit_line(line)
            if parsed:
                results.append(parsed)
        return results

    def _parse_audit_line(self, line: str) -> Optional[Dict[str, Any]]:
        type_match = re.search(r"type=([A-Z_]+)", line)
        audit_type = type_match.group(1) if type_match else "SYSCALL"

        time_match = re.search(r"msg=audit\((\d+\.\d+):", line)
        ts_str = datetime.now(timezone.utc).isoformat()
        if time_match:
            try:
                ts_str = datetime.fromtimestamp(float(time_match.group(1)), tz=timezone.utc).isoformat()
            except Exception:
                pass

        # Extract Key-Value pairs
        pairs = dict(re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line))
        cleaned_pairs = {k: v[0] if v[0] else v[1] for k, v in pairs.items()}

        exe = cleaned_pairs.get("exe", "")
        comm = cleaned_pairs.get("comm", "")
        uid = cleaned_pairs.get("uid", "0")
        acct = cleaned_pairs.get("acct", "root")
        addr = cleaned_pairs.get("addr", "127.0.0.1")
        hostname = cleaned_pairs.get("hostname", "linux-node-01")
        res = cleaned_pairs.get("res", "success")

        severity = "LOW"
        if audit_type == "AVC": # AppArmor / SELinux denial
            severity = "HIGH"
        elif audit_type == "USER_LOGIN" and res in ["failed", "0"]:
            severity = "HIGH"
        elif exe in ["/bin/chmod", "/usr/bin/sudo", "/bin/nc", "/usr/bin/nmap", "/bin/bash", "/usr/bin/curl"]:
            severity = "MEDIUM"

        return {
            "timestamp": ts_str,
            "source": "linux_auditd",
            "source_ip": addr if addr != "?" else "127.0.0.1",
            "destination_ip": "10.0.0.1",
            "port": 22,
            "protocol": "TCP",
            "username": acct if acct != "?" else f"uid_{uid}",
            "hostname": hostname,
            "event_type": f"LINUX_AUDITD_{audit_type}",
            "category": "Endpoint Host Activity",
            "action": f"Executed {comm or exe or audit_type}",
            "severity": severity,
            "status": "SUCCESS" if res in ["1", "success"] else "FAILURE",
            "resource": exe or comm or audit_type,
            "raw_message": line,
            "metadata_json": {
                "audit_type": audit_type,
                "executable": exe,
                "command": comm,
                "uid": uid,
                "key_values": cleaned_pairs
            }
        }


class CloudAuditParser(BaseParser):
    """Parser for AWS CloudTrail & Google Cloud Audit telemetry logs."""

    def can_parse(self, content: str) -> bool:
        if '"eventSource":' in content and ('"awsRegion":' in content or '"userIdentity":' in content):
            return True
        if '"protoPayload":' in content and '"serviceName":' in content: # GCP Audit
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            data = json.loads(content)
            # Handle CloudTrail "Records" array
            records = data.get("Records", [data]) if isinstance(data, dict) else data
            for record in records:
                results.append(self._normalize_cloud_record(record))
        except Exception:
            for line in content.strip().splitlines():
                if line.strip().startswith("{"):
                    try:
                        record = json.loads(line)
                        results.append(self._normalize_cloud_record(record))
                    except Exception:
                        pass
        return results

    def _normalize_cloud_record(self, r: Dict[str, Any]) -> Dict[str, Any]:
        # AWS CloudTrail vs GCP Audit normalization
        if "eventSource" in r:
            event_name = r.get("eventName", "CloudTrailEvent")
            user_id = r.get("userIdentity", {}).get("userName") or r.get("userIdentity", {}).get("principalId") or "iam_user"
            src_ip = r.get("sourceIPAddress", "0.0.0.0")
            source = f"aws_{r.get('eventSource', 'cloudtrail').split('.')[0]}"
            error_code = r.get("errorCode")

            severity = "LOW"
            if event_name in ["CreateAccessKey", "AttachUserPolicy", "PutBucketPolicy", "StopLogging", "DeleteTrail"]:
                severity = "HIGH"
            elif error_code in ["AccessDenied", "UnauthorizedOperation"]:
                severity = "MEDIUM"

            return {
                "timestamp": r.get("eventTime", datetime.now(timezone.utc).isoformat()),
                "source": source,
                "source_ip": src_ip,
                "destination_ip": "169.254.169.254",
                "port": 443,
                "protocol": "HTTPS",
                "username": user_id,
                "hostname": r.get("awsRegion", "us-east-1"),
                "event_type": f"AWS_{event_name.upper()}",
                "category": "Cloud Control Plane",
                "action": event_name,
                "severity": severity,
                "status": "FAILURE" if error_code else "SUCCESS",
                "resource": r.get("requestParameters", {}).get("bucketName") or r.get("requestParameters", {}).get("userName") or event_name,
                "raw_message": json.dumps(r),
                "metadata_json": r
            }
        else:
            # GCP Audit Log
            proto = r.get("protoPayload", {})
            method_name = proto.get("methodName", "GCPMethod")
            principal = proto.get("authenticationInfo", {}).get("principalEmail", "service_account")
            caller_ip = proto.get("requestMetadata", {}).get("callerIp", "0.0.0.0")

            return {
                "timestamp": r.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "source": "gcp_audit",
                "source_ip": caller_ip,
                "destination_ip": "googleapis.com",
                "port": 443,
                "protocol": "HTTPS",
                "username": principal,
                "hostname": r.get("resource", {}).get("labels", {}).get("project_id", "gcp-project"),
                "event_type": f"GCP_{method_name.replace('.', '_').upper()}",
                "category": "Cloud IAM & Resource",
                "action": method_name,
                "severity": "HIGH" if "setIamPolicy" in method_name or "delete" in method_name else "LOW",
                "status": "SUCCESS" if proto.get("status", {}).get("code", 0) == 0 else "FAILURE",
                "resource": proto.get("resourceName", method_name),
                "raw_message": json.dumps(r),
                "metadata_json": r
            }

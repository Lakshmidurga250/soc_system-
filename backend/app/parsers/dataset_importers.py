"""Public Cybersecurity Dataset Importers & Parsers for SentinelAI.

Supports standard benchmark datasets:
- CICIDS2017 (Canadian Institute for Cybersecurity)
- CSE-CIC-IDS2018
- UNSW-NB15 (University of New South Wales)
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Dict, Generator, List, Optional, Any

# Standard column mappings for CICIDS2017 flow files
CICIDS2017_COLUMNS = {
    "source_ip": ["Source IP", "src_ip", "Src IP"],
    "destination_ip": ["Destination IP", "dst_ip", "Dst IP"],
    "source_port": ["Source Port", "src_port", "Src Port"],
    "destination_port": ["Destination Port", "dst_port", "Dst Port"],
    "protocol": ["Protocol", "protocol"],
    "timestamp": ["Timestamp", "timestamp", "Time"],
    "label": ["Label", "label", "Attack"],
    "flow_duration": ["Flow Duration", "flow_duration"],
    "total_fwd_packets": ["Total Fwd Packets", "tot_fwd_pkts"],
    "total_bwd_packets": ["Total Backward Packets", "tot_bwd_pkts"],
}

# Standard column mappings for UNSW-NB15 flow files
UNSW_NB15_COLUMNS = {
    "source_ip": ["srcip", "source_ip"],
    "destination_ip": ["dstip", "destination_ip"],
    "source_port": ["sport", "src_port"],
    "destination_port": ["dsport", "dst_port"],
    "protocol": ["proto", "protocol"],
    "label": ["attack_cat", "label"],
    "dur": ["dur", "duration"],
    "sbytes": ["sbytes", "src_bytes"],
    "dbytes": ["dbytes", "dst_bytes"],
}

# Attack Label Normalization Mapping
ATTACK_LABEL_MAP: Dict[str, Dict[str, str]] = {
    "benign": {"category": "Normal", "severity": "INFORMATIONAL", "event_type": "network_flow"},
    "normal": {"category": "Normal", "severity": "INFORMATIONAL", "event_type": "network_flow"},
    "dos": {"category": "DoS", "severity": "HIGH", "event_type": "dos_attack"},
    "ddos": {"category": "DDoS", "severity": "CRITICAL", "event_type": "ddos_flood"},
    "dos slowloris": {"category": "DoS", "severity": "HIGH", "event_type": "slowloris_attack"},
    "dos slowhttptest": {"category": "DoS", "severity": "HIGH", "event_type": "slowhttp_attack"},
    "dos hulk": {"category": "DoS", "severity": "HIGH", "event_type": "hulk_flood"},
    "dos goldeneye": {"category": "DoS", "severity": "HIGH", "event_type": "goldeneye_flood"},
    "portscan": {"category": "Port Scan", "severity": "MEDIUM", "event_type": "port_scan"},
    "port scan": {"category": "Port Scan", "severity": "MEDIUM", "event_type": "port_scan"},
    "reconnaissance": {"category": "Network Scan", "severity": "MEDIUM", "event_type": "network_scan"},
    "bot": {"category": "Bot Activity", "severity": "HIGH", "event_type": "botnet_c2"},
    "botnet": {"category": "Bot Activity", "severity": "HIGH", "event_type": "botnet_c2"},
    "web attack": {"category": "Web Attack", "severity": "HIGH", "event_type": "web_exploit"},
    "web attack – brute force": {"category": "Brute Force", "severity": "HIGH", "event_type": "brute_force"},
    "web attack – xss": {"category": "Web Attack", "severity": "HIGH", "event_type": "xss_injection"},
    "web attack – sql injection": {"category": "Web Attack", "severity": "CRITICAL", "event_type": "sql_injection"},
    "sql injection": {"category": "Web Attack", "severity": "CRITICAL", "event_type": "sql_injection"},
    "brute force": {"category": "Brute Force", "severity": "HIGH", "event_type": "brute_force"},
    "ftp-patator": {"category": "Brute Force", "severity": "HIGH", "event_type": "ftp_bruteforce"},
    "ssh-patator": {"category": "Brute Force", "severity": "HIGH", "event_type": "ssh_bruteforce"},
    "infiltration": {"category": "Privilege Escalation", "severity": "CRITICAL", "event_type": "lateral_infiltration"},
    "privilege escalation": {"category": "Privilege Escalation", "severity": "CRITICAL", "event_type": "privilege_escalation"},
    "backdoor": {"category": "Malware", "severity": "CRITICAL", "event_type": "backdoor_trojan"},
    "exploits": {"category": "Web Attack", "severity": "HIGH", "event_type": "generic_exploit"},
    "fuzzers": {"category": "Network Scan", "severity": "LOW", "event_type": "protocol_fuzzing"},
    "generic": {"category": "Anomalous Activity", "severity": "MEDIUM", "event_type": "anomalous_flow"},
    "analysis": {"category": "Network Scan", "severity": "LOW", "event_type": "recon_probe"},
    "worms": {"category": "Malware", "severity": "CRITICAL", "event_type": "worm_propagation"},
    "ransomware": {"category": "Ransomware", "severity": "CRITICAL", "event_type": "ransomware_encryption"},
    "data exfiltration": {"category": "Data Exfiltration", "severity": "CRITICAL", "event_type": "data_exfiltration"},
}

def map_attack_label(raw_label: str) -> Dict[str, str]:
    """Map raw public dataset label to standardized SentinelAI attack taxonomy."""
    if not raw_label:
        return {"category": "Normal", "severity": "INFORMATIONAL", "event_type": "network_flow"}
    cleaned = raw_label.strip().lower()
    for key, val in sorted(ATTACK_LABEL_MAP.items(), key=lambda x: len(x[0]), reverse=True):
        if key in cleaned:
            return val
    return {"category": "Anomalous Activity", "severity": "MEDIUM", "event_type": "generic_attack"}

def _get_val(row: Dict[str, Any], candidate_keys: List[str], default: Any = None) -> Any:
    for k in candidate_keys:
        if k in row and row[k] is not None and str(row[k]).strip() != "":
            return row[k]
    # Check case-insensitive match
    for row_k, row_v in row.items():
        for cand in candidate_keys:
            if row_k.strip().lower() == cand.strip().lower():
                return row_v
    return default

class DatasetImporter:
    """Parser & batch importer for public benchmark cybersecurity datasets."""

    @staticmethod
    def parse_cicids2017_csv(content: str, max_records: int = 1000) -> List[Dict[str, Any]]:
        """Parse CSV rows from CICIDS2017 / CSE-CIC-IDS2018 format."""
        events = []
        reader = csv.DictReader(io.StringIO(content))
        for idx, row in enumerate(reader):
            if idx >= max_records:
                break
            
            src_ip = _get_val(row, CICIDS2017_COLUMNS["source_ip"], "192.168.10.50")
            dst_ip = _get_val(row, CICIDS2017_COLUMNS["destination_ip"], "172.16.0.1")
            src_port = int(float(_get_val(row, CICIDS2017_COLUMNS["source_port"], 49152)))
            dst_port = int(float(_get_val(row, CICIDS2017_COLUMNS["destination_port"], 80)))
            raw_label = str(_get_val(row, CICIDS2017_COLUMNS["label"], "BENIGN"))
            
            mapped = map_attack_label(raw_label)
            
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "CICIDS2017_DATASET",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "event_type": mapped["event_type"],
                "category": mapped["category"],
                "severity": mapped["severity"],
                "status": "FAILURE" if mapped["category"] != "Normal" else "SUCCESS",
                "resource": f"port:{dst_port}",
                "synthetic": False,
                "metadata_json": {
                    "dataset": "CICIDS2017",
                    "original_label": raw_label,
                    "flow_duration": _get_val(row, CICIDS2017_COLUMNS["flow_duration"], 0),
                }
            })
        return events

    @staticmethod
    def parse_unsw_nb15_csv(content: str, max_records: int = 1000) -> List[Dict[str, Any]]:
        """Parse CSV rows from UNSW-NB15 format."""
        events = []
        reader = csv.DictReader(io.StringIO(content))
        for idx, row in enumerate(reader):
            if idx >= max_records:
                break
            
            src_ip = _get_val(row, UNSW_NB15_COLUMNS["source_ip"], "10.40.85.1")
            dst_ip = _get_val(row, UNSW_NB15_COLUMNS["destination_ip"], "149.171.126.1")
            src_port = int(float(_get_val(row, UNSW_NB15_COLUMNS["source_port"], 1024)))
            dst_port = int(float(_get_val(row, UNSW_NB15_COLUMNS["destination_port"], 443)))
            raw_label = str(_get_val(row, UNSW_NB15_COLUMNS["label"], "Normal"))
            
            mapped = map_attack_label(raw_label)
            
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "UNSW_NB15_DATASET",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "event_type": mapped["event_type"],
                "category": mapped["category"],
                "severity": mapped["severity"],
                "status": "FAILURE" if mapped["category"] != "Normal" else "SUCCESS",
                "resource": f"proto:{_get_val(row, UNSW_NB15_COLUMNS['protocol'], 'tcp')}",
                "synthetic": False,
                "metadata_json": {
                    "dataset": "UNSW-NB15",
                    "original_label": raw_label,
                    "dur": _get_val(row, UNSW_NB15_COLUMNS["dur"], 0),
                    "sbytes": _get_val(row, UNSW_NB15_COLUMNS["sbytes"], 0),
                    "dbytes": _get_val(row, UNSW_NB15_COLUMNS["dbytes"], 0),
                }
            })
        return events

dataset_importer = DatasetImporter()

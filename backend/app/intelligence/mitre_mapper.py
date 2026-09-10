"""Local MITRE ATT&CK Matrix & Technique Mapping Module for SentinelAI."""
from typing import Dict, List, Any, Optional

MITRE_MATRIX: Dict[str, Dict[str, Any]] = {
    "Brute Force": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force: Password Guessing & Password Spraying",
        "technique_id": "T1110",
        "subtechnique_id": "T1110.001",
        "description": "Adversaries may use brute force techniques to attempt authentication by iteratively guessing passwords against valid user accounts.",
        "mitigation": "Account lockout policies, multi-factor authentication (MFA), rate limiting authentication endpoints.",
        "detection_signatures": ["Failed password for root", "EventID 4625", "Rapid authentication burst"]
    },
    "Port Scan": {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "subtechnique_id": "T1046",
        "description": "Adversaries may attempt to discover active network services and open listening ports across target subnetworks.",
        "mitigation": "Network segmentation, stateful firewall inspection, disabling unnecessary services and ports.",
        "detection_signatures": ["SYN scan burst", "Sequential destination port probing", "ICMP sweep"]
    },
    "Network Scan": {
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "technique": "Active Scanning: Scanning IP Blocks",
        "technique_id": "T1595",
        "subtechnique_id": "T1595.001",
        "description": "Adversaries execute automated IP sweeps and port sweeps to map organization perimeter assets prior to targeting.",
        "mitigation": "Perimeter IDS/IPS, blocking known hostile IP ranges, darknet honeypots.",
        "detection_signatures": ["Rapid connection attempts across CIDR block", "Host discovery probes"]
    },
    "DoS": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Endpoint Denial of Service: Service Exhaustion",
        "technique_id": "T1499",
        "subtechnique_id": "T1499.002",
        "description": "Adversaries may perform endpoint or application service exhaustion to degrade or deny availability of critical services.",
        "mitigation": "Connection rate limiting, reverse proxy caching, web application firewall (WAF).",
        "detection_signatures": ["Slowloris partial HTTP requests", "HTTP request flooding", "Thread exhaustion"]
    },
    "DDoS": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Network Denial of Service: Direct Network Flood",
        "technique_id": "T1498",
        "subtechnique_id": "T1498.001",
        "description": "Adversaries flood the target network infrastructure with high-volume volumetric traffic to saturate bandwidth.",
        "mitigation": "Upstream DDoS mitigation scrubbing, BGP Anycast routing, SYN cookies.",
        "detection_signatures": ["Gigabit UDP/SYN flood", "Bandwidth saturation", "Anomalous ingress volume"]
    },
    "Web Attack": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "subtechnique_id": "T1190",
        "description": "Adversaries exploit vulnerabilities (SQL injection, XSS, Path Traversal) in public-facing web applications to execute unauthorized commands.",
        "mitigation": "Input parameter sanitization, parameterized queries, modern WAF rule sets, secure coding.",
        "detection_signatures": ["UNION SELECT syntax", "' OR '1'='1", "<script> injection", "../ path traversal"]
    },
    "Privilege Escalation": {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Valid Accounts: Domain & Local Admin Accounts",
        "technique_id": "T1078",
        "subtechnique_id": "T1078.002",
        "description": "Adversaries obtain and abuse credentials of existing administrative accounts or exploit kernel flaws to elevate access.",
        "mitigation": "Principle of least privilege (PoLP), Just-In-Time (JIT) admin elevation, Privileged Access Management (PAM).",
        "detection_signatures": ["EventID 4672", "sudoers file edit", "Non-admin executing privileged binaries"]
    },
    "Data Exfiltration": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over C2 Channel & Web Service",
        "technique_id": "T1048",
        "subtechnique_id": "T1048.003",
        "description": "Adversaries steal sensitive databases or files by transmitting them over encrypted tunnels or cloud storage APIs.",
        "mitigation": "Data Loss Prevention (DLP), outbound traffic egress inspection, proxy domain filtering.",
        "detection_signatures": ["Anomalous outbound byte volume", "Mega/Dropbox API upload spikes", "DNS tunneling"]
    },
    "Malware": {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter: PowerShell / Windows Command Shell",
        "technique_id": "T1059",
        "subtechnique_id": "T1059.001",
        "description": "Adversaries execute malicious payloads using built-in system interpreters like PowerShell, bash, or CMD.",
        "mitigation": "PowerShell Constrained Language Mode, script block logging, endpoint behavioral EDR.",
        "detection_signatures": ["EncodedCommand execution", "Bypass execution policy", "DownloadString web invocation"]
    },
    "Bot Activity": {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Application Layer Protocol: Web Protocols",
        "technique_id": "T1071",
        "subtechnique_id": "T1071.001",
        "description": "Compromised endpoints communicate with adversary command and control servers using regular HTTP/HTTPS beacons.",
        "mitigation": "TLS inspection, C2 threat intelligence blocklists, beaconing jitter analysis.",
        "detection_signatures": ["Periodic heartbeat intervals", "Known botnet User-Agent", "DGA domain queries"]
    },
    "Ransomware": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Data Encrypted for Impact",
        "technique_id": "T1486",
        "subtechnique_id": "T1486",
        "description": "Adversaries encrypt critical operational data and system files on target hosts to interrupt availability and extort ransom.",
        "mitigation": "Immutable offsite backups, volume shadow copy protection, automated endpoint canary file traps.",
        "detection_signatures": ["Mass file extension modification", "vssadmin delete shadows", "High-velocity disk writes"]
    },
    "Anomalous Activity": {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Impair Defenses: Disable or Modify Tools",
        "technique_id": "T1562",
        "subtechnique_id": "T1562.001",
        "description": "Adversaries disable security logging, antivirus sensors, or firewall rules to prevent detection of unauthorized activity.",
        "mitigation": "Tamper protection for EDR, centralized write-once SIEM logging, integrity monitoring.",
        "detection_signatures": ["EventID 1102 log cleared", "sc stop WinDefend", "Registry modification in security keys"]
    }
}

class MitreMapper:
    """Provides MITRE ATT&CK context, tactics, techniques, and mitigation guidance."""

    @staticmethod
    def map_category(attack_category: str) -> Dict[str, Any]:
        """Return MITRE ATT&CK mapping for a given threat category."""
        clean = (attack_category or "").strip().lower()
        if "credential" in clean or "stuffing" in clean or "brute" in clean or "password" in clean:
            return MITRE_MATRIX["Brute Force"]
        if "port" in clean or "recon" in clean:
            return MITRE_MATRIX["Port Scan"]
        if "exfil" in clean or "leak" in clean:
            return MITRE_MATRIX["Data Exfiltration"]
        if "ransom" in clean:
            return MITRE_MATRIX["Ransomware"]
        if "privilege" in clean or "elevation" in clean:
            return MITRE_MATRIX["Privilege Escalation"]
        if "sql" in clean or "web" in clean or "xss" in clean:
            return MITRE_MATRIX["Web Attack"]
        if "dos" in clean or "flood" in clean:
            return MITRE_MATRIX["DoS"]

        for cat_name, mapping in MITRE_MATRIX.items():
            if cat_name.lower() in clean:
                return mapping
        return {
            "tactic": "Unclassified",
            "tactic_id": "TA0000",
            "technique": "Generic Adversary Activity",
            "technique_id": "T0000",
            "subtechnique_id": "T0000",
            "description": "Observed activity deviates from normal operational baseline but does not match specific signature.",
            "mitigation": "Conduct baseline forensic inspection and review endpoint logs.",
            "detection_signatures": ["Statistical deviation"]
        }

    @staticmethod
    def get_full_matrix() -> List[Dict[str, Any]]:
        """Return the complete local MITRE ATT&CK reference taxonomy."""
        matrix = []
        for cat, details in MITRE_MATRIX.items():
            item = {"category": cat, **details}
            matrix.append(item)
        return matrix

mitre_mapper = MitreMapper()

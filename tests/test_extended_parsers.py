from backend.app.parsers.syslog_parser import SyslogParser
from backend.app.parsers.cef_parser import CEFParser
from backend.app.parsers.windows_parser import WindowsEventParser

def test_syslog_rfc3164_parser():
    parser = SyslogParser()
    payload = b"<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2"
    records = list(parser.parse(payload))
    assert len(records) == 1
    rec = records[0].values
    assert rec["hostname"] == "myhost"
    assert rec["source_ip"] == "192.168.1.100"
    assert rec["username"] == "root"
    assert rec["status"] == "FAILURE"

def test_syslog_rfc5424_parser():
    parser = SyslogParser()
    payload = b"<165>1 2026-09-10T20:30:00.000Z srv01 webapp 5566 ID47 - Access denied for user admin from 10.0.0.5"
    records = list(parser.parse(payload))
    assert len(records) == 1
    rec = records[0].values
    assert rec["hostname"] == "srv01"
    assert rec["source_ip"] == "10.0.0.5"
    assert rec["username"] == "admin"
    assert rec["status"] == "FAILURE"

def test_cef_parser():
    parser = CEFParser()
    payload = b"CEF:0|SecurityCorp|Firewall|1.0|100|Port Scan Detected|8|src=203.0.113.15 dst=10.0.0.1 suser=attacker act=blocked"
    records = list(parser.parse(payload))
    assert len(records) == 1
    rec = records[0].values
    assert rec["source_ip"] == "203.0.113.15"
    assert rec["username"] == "attacker"
    assert rec["severity"] == "CRITICAL"
    assert rec["status"] == "FAILURE"

def test_windows_xml_parser():
    parser = WindowsEventParser()
    payload = b"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-09-10T20:00:00.000Z"/>
    <Computer>CORP-DC01.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_backup</Data>
    <Data Name="IpAddress">192.168.10.55</Data>
    <Data Name="IpPort">445</Data>
  </EventData>
</Event>"""
    records = list(parser.parse(payload))
    assert len(records) == 1
    rec = records[0].values
    assert rec["event_type"] == "WinEvent_4625"
    assert rec["hostname"] == "CORP-DC01.local"
    assert rec["username"] == "svc_backup"
    assert rec["source_ip"] == "192.168.10.55"
    assert rec["status"] == "FAILURE"

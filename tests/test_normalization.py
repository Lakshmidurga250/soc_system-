from backend.app.parsers.base_parser import ParsedRecord, ParserError
from backend.app.services.normalization import normalize

def test_normalizes_aliases_into_canonical_event():
    event=normalize(ParsedRecord({"time":"2026-01-01T09:00:00Z","src_ip":"198.51.100.4","user":"alex","type":"login","outcome":"FAILURE"},1),"upload")
    assert event["source_ip"] == "198.51.100.4"
    assert event["username"] == "alex"
    assert event["event_type"] == "login"
    assert event["status"] == "FAILURE"

def test_rejects_event_without_type():
    try: normalize(ParsedRecord({"user":"alex"},1),"upload")
    except ParserError as exc: assert "event_type" in str(exc)
    else: raise AssertionError("missing event type should fail")

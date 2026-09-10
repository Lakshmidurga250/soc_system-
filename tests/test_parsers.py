from backend.app.parsers import CSVParser, JSONParser

def test_csv_parser_skips_empty_lines():
    records=list(CSVParser().parse(b"event_type,source_ip\nlogin,198.51.100.1\n\n"))
    assert len(records)==1 and records[0].row_number==2

def test_jsonl_parser_reads_each_object():
    records=list(JSONParser().parse(b'{"event_type":"login"}\n{"event_type":"web"}'))
    assert [record.values["event_type"] for record in records]==["login","web"]

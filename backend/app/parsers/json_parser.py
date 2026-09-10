import json
from .base_parser import BaseParser, ParsedRecord, ParserError

class JSONParser(BaseParser):
    supported_extensions=(".json", ".jsonl", ".ndjson")
    def parse(self,payload:bytes):
        try: text=payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc: raise ParserError("JSON must be UTF-8 text") from exc
        try: document=json.loads(text)
        except json.JSONDecodeError:
            try: document=[json.loads(line) for line in text.splitlines() if line.strip()]
            except json.JSONDecodeError as exc: raise ParserError(f"Invalid JSON: {exc.msg}") from exc
        records=document if isinstance(document,list) else document.get("events",[document]) if isinstance(document,dict) else None
        if not isinstance(records,list): raise ParserError("JSON must be an object, an events object, or an array")
        for index,item in enumerate(records,start=1):
            if not isinstance(item,dict): raise ParserError(f"Record {index} is not an object")
            yield ParsedRecord(item,index)

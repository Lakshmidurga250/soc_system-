import csv
import io
from .base_parser import BaseParser, ParsedRecord, ParserError

class CSVParser(BaseParser):
    supported_extensions=(".csv",)
    def parse(self, payload: bytes):
        try: text=payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            try: text=payload.decode("latin-1")
            except UnicodeDecodeError as exc: raise ParserError("File is not UTF-8 or Latin-1 text") from exc
        reader=csv.DictReader(io.StringIO(text))
        if not reader.fieldnames: raise ParserError("CSV must include a header row")
        for index,row in enumerate(reader,start=2):
            if not any(str(value).strip() for value in row.values() if value): continue
            yield ParsedRecord({str(k).strip():v for k,v in row.items() if k is not None},index)

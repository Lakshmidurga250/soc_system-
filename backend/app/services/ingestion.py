import hashlib
import os
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from ..models import IngestionBatch, SecurityEvent
from ..parsers import PARSERS
from ..parsers.base_parser import ParserError
from .features import extract_event_features
from .normalization import normalize

def detect_format(filename: str, content_type: str | None) -> str:
    extension = os.path.splitext(filename.lower())[1]
    if extension == ".csv" or content_type in {"text/csv", "application/csv"}:
        return "csv"
    if extension in {".json", ".jsonl", ".ndjson"} or content_type in {"application/json", "application/x-ndjson"}:
        return "json"
    if extension in {".syslog", ".log"} or content_type in {"text/plain", "application/x-syslog"}:
        return "syslog"
    if extension == ".cef":
        return "cef"
    if extension in {".xml", ".evtx_xml"} or content_type in {"text/xml", "application/xml"}:
        return "windows"
    raise ParserError(f"Unsupported file format '{extension}'. Supported formats: CSV, JSON, JSONL, Syslog (.log/.syslog), CEF (.cef), Windows XML (.xml)")

def ingest_upload(db: Session, *, filename: str, content_type: str | None, payload: bytes, source: str = "upload") -> IngestionBatch:
    source_format = detect_format(filename, content_type)
    digest = hashlib.sha256(payload).hexdigest()
    batch = IngestionBatch(filename=filename, source_format=source_format, source=source, checksum=digest)
    db.add(batch)
    db.flush()
    parser = PARSERS[source_format]
    try:
        records = list(parser.parse(payload))
    except ParserError as exc:
        batch.errors = [{"record": None, "error": str(exc)}]
        batch.malformed_records = 1
        return batch

    batch.total_records = len(records)
    for record in records:
        try:
            data = normalize(record, source)
            event_digest = hashlib.sha256(repr(sorted(data.items())).encode()).hexdigest()
            with db.begin_nested():
                event = SecurityEvent(event_id=event_digest, **data)
                db.add(event)
                db.flush()
                extract_event_features(db, event)
            batch.accepted_records += 1
        except IntegrityError:
            batch.duplicate_records += 1
        except (ParserError, ValueError, TypeError) as exc:
            batch.malformed_records += 1
            if len(batch.errors) < 100:
                batch.errors.append({"record": record.row_number, "error": str(exc)})
    return batch

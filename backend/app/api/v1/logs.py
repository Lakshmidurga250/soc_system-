"""Multi-Format Log File Ingestion and Batch History endpoints."""
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...core.config import settings
from ...models import IngestionBatch, SecurityEvent
from ...parsers.base_parser import ParserError
from ...services.ingestion import ingest_upload
from ...engines.detection_engine import detection_engine
from ...services.audit import audit
from ..deps import require_roles, current_user

router = APIRouter(prefix="/logs", tags=["Log Ingestion"])

@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user = Depends(require_roles("ADMIN", "SOC_ANALYST"))
):
    if not file.filename:
        raise HTTPException(status_code=422, detail="A filename is required")
    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=422, detail="Uploaded file is empty")
    if len(payload) > settings.upload_max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.upload_max_bytes} byte limit")

    try:
        batch = ingest_upload(db, filename=file.filename, content_type=file.content_type, payload=payload)
    except ParserError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    db.flush()
    # Evaluate rules on newly ingested records
    events = db.query(SecurityEvent).filter(SecurityEvent.source == batch.source_format).order_by(desc(SecurityEvent.created_at)).limit(batch.accepted_records).all()
    alert_count = sum(len(detection_engine.evaluate_event(db, evt)) for evt in events)

    audit(db, "LOG_FILE_UPLOADED", f"batch:{batch.id}", user.id, filename=file.filename, accepted=batch.accepted_records, alerts=alert_count)
    db.commit()

    return {
        "batch_id": batch.id,
        "filename": batch.filename,
        "format": batch.source_format,
        "total_records": batch.total_records,
        "accepted_records": batch.accepted_records,
        "duplicate_records": batch.duplicate_records,
        "malformed_records": batch.malformed_records,
        "errors": batch.errors,
        "alerts_created": alert_count,
    }

@router.get("/ingestions")
def get_ingestion_history(db: Session = Depends(get_db), user = Depends(current_user)):
    items = db.scalars(select(IngestionBatch).order_by(desc(IngestionBatch.created_at)).limit(50)).all()
    return {
        "items": [
            {
                "id": x.id,
                "filename": x.filename,
                "format": x.source_format,
                "total_records": x.total_records,
                "accepted_records": x.accepted_records,
                "created_at": x.created_at.isoformat() if x.created_at else None,
            }
            for x in items
        ]
    }

"""Detection Alerts Queue, Deduplication & Triage Endpoints."""
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, or_, and_, desc
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...models import Alert
from ...schemas.domain import StatusUpdate
from ...repositories import AlertRepository
from ...services.audit import audit
from ...engines.deduplication_engine import deduplication_engine
from ..deps import current_user

router = APIRouter(prefix="/alerts", tags=["Alerts"])

class BulkStatusUpdate(BaseModel):
    alert_ids: List[str]
    status: str = Field(pattern="^(NEW|INVESTIGATING|CONFIRMED|FALSE_POSITIVE|RESOLVED|CLOSED)$")
    note: Optional[str] = None

@router.get("")
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
    user = Depends(current_user),
):
    stmt = select(Alert)
    
    if status and status != "ALL":
        stmt = stmt.where(Alert.status == status)
    if severity and severity != "ALL":
        stmt = stmt.where(Alert.severity == severity)
    if q:
        search = f"%{q}%"
        stmt = stmt.where(
            or_(
                Alert.title.ilike(search),
                Alert.description.ilike(search),
                Alert.source.ilike(search),
            )
        )
    
    total = db.scalar(select(Alert.id).select_from(stmt.subquery()).with_only_columns(Alert.id))
    # Count total matching
    total_count = len(db.scalars(stmt).all())
    
    offset = (page - 1) * page_size
    items = db.scalars(stmt.order_by(desc(Alert.created_at)).offset(offset).limit(page_size)).all()

    return {
        "items": [
            {
                "id": x.id,
                "title": x.title,
                "description": x.description,
                "severity": x.severity,
                "risk_score": x.risk_score,
                "confidence_score": x.confidence_score,
                "status": x.status,
                "source": x.source,
                "detection_method": x.detection_method,
                "created_at": x.created_at.isoformat() if x.created_at else None,
                "explanation": x.explanation,
                "entities": x.entities,
                "event_ids": x.event_ids or [],
                "event_count": len(x.event_ids or []),
                "notes": x.notes or [],
            }
            for x in items
        ],
        "total": total_count,
        "page": page,
        "page_size": page_size,
    }

@router.get("/metrics/deduplication")
def get_deduplication_metrics(db: Session = Depends(get_db), user = Depends(current_user)):
    """Retrieve SOC alert noise reduction and deduplication metrics."""
    return deduplication_engine.calculate_deduplication_metrics(db)

@router.get("/{alert_id}")
def get_alert_detail(alert_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    repo = AlertRepository(db)
    alert = repo.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "confidence_score": alert.confidence_score,
        "status": alert.status,
        "source": alert.source,
        "detection_method": alert.detection_method,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "explanation": alert.explanation,
        "entities": alert.entities,
        "event_ids": alert.event_ids or [],
        "notes": alert.notes or [],
    }

@router.patch("/{alert_id}")
def update_alert_status(alert_id: str, payload: StatusUpdate, db: Session = Depends(get_db), user = Depends(current_user)):
    repo = AlertRepository(db)
    alert = repo.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status
    notes = list(alert.notes or [])
    if payload.note:
        notes.append({"author": user.id, "note": payload.note, "at": datetime.now(timezone.utc).isoformat()})
    alert.notes = notes
    audit(db, "ALERT_STATUS_UPDATED", f"alert:{alert.id}", user.id, new_status=payload.status)
    db.commit()
    return {"id": alert.id, "status": alert.status}

@router.post("/bulk-status")
def bulk_update_alert_status(payload: BulkStatusUpdate, db: Session = Depends(get_db), user = Depends(current_user)):
    """Bulk update multiple alerts (e.g. mark False Positive or Confirmed)."""
    updated_count = 0
    now_str = datetime.now(timezone.utc).isoformat()
    for aid in payload.alert_ids:
        alert = db.get(Alert, aid)
        if alert:
            alert.status = payload.status
            notes = list(alert.notes or [])
            if payload.note:
                notes.append({"author": user.id, "note": f"[BULK] {payload.note}", "at": now_str})
            alert.notes = notes
            updated_count += 1
    
    audit(db, "ALERT_BULK_STATUS_UPDATED", f"alerts:{len(payload.alert_ids)}", user.id, new_status=payload.status)
    db.commit()
    return {"status": "success", "updated_count": updated_count, "new_status": payload.status}

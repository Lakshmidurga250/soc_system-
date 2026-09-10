"""Security Event Telemetry endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import SecurityEvent
from ...schemas.domain import EventCreate, EventOut
from ...repositories import EventRepository
from ...engines.feature_engine import feature_engine
from ...engines.detection_engine import detection_engine
from ...services.audit import audit
from ..deps import current_user

router = APIRouter(prefix="/events", tags=["Security Events"])

@router.get("")
def list_events(
    page: int = 1,
    page_size: int = 50,
    severity: str | None = None,
    q: str | None = None,
    db: Session = Depends(get_db),
    user = Depends(current_user)
):
    repo = EventRepository(db)
    items, total = repo.search_events(query=q, severity=severity, page=page, page_size=min(page_size, 100))
    return {
        "items": [EventOut.model_validate(x).model_dump() for x in items],
        "total": total,
        "page": page,
        "page_size": min(page_size, 100)
    }

@router.post("", response_model=EventOut)
def create_single_event(payload: EventCreate, db: Session = Depends(get_db), user = Depends(current_user)):
    evt = SecurityEvent(**payload.model_dump(exclude={"timestamp"}), timestamp=payload.timestamp)
    db.add(evt)
    db.flush()
    feature_engine.extract_features(db, evt)
    alerts = detection_engine.evaluate_event(db, evt)
    audit(db, "EVENT_CREATED", f"event:{evt.id}", user.id, alerts_created=len(alerts))
    db.commit()
    db.refresh(evt)
    return evt

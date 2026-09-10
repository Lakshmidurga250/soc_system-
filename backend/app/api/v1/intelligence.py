"""Threat Intelligence & Local IOC Management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import ThreatIndicator
from ...schemas.domain import IndicatorCreate
from ...services.audit import audit
from ..deps import current_user, require_roles

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])

@router.get("/indicators")
def list_indicators(db: Session = Depends(get_db), user = Depends(current_user)):
    items = db.scalars(select(ThreatIndicator).order_by(desc(ThreatIndicator.created_at))).all()
    return {
        "items": [
            {
                "id": x.id,
                "indicator": x.indicator,
                "indicator_type": x.indicator_type,
                "risk_level": x.risk_level,
                "description": x.description,
                "source": x.source,
                "status": x.status,
            }
            for x in items
        ]
    }

@router.post("/indicators")
def add_indicator(payload: IndicatorCreate, db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    if db.scalar(select(ThreatIndicator).where(ThreatIndicator.indicator == payload.indicator)):
        raise HTTPException(status_code=409, detail="Threat indicator already exists in feed")
    item = ThreatIndicator(**payload.model_dump())
    db.add(item)
    audit(db, "IOC_INDICATOR_CREATED", f"indicator:{item.id}", user.id, indicator=item.indicator)
    db.commit()
    return {"id": item.id, "indicator": item.indicator, "status": item.status}

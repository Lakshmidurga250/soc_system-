"""Behavioral Analytics & Historical Entity Profile endpoints."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...engines.behavior_engine import behavior_engine
from ..deps import current_user

router = APIRouter(prefix="/behavior", tags=["Behavior Analytics"])

@router.get("/profile")
def get_entity_profile(
    entity_type: str = Query(..., description="user, host, or ip"),
    entity_value: str = Query(...),
    db: Session = Depends(get_db),
    user = Depends(current_user)
):
    return behavior_engine.get_entity_profile(db, entity_type=entity_type, entity_value=entity_value)
